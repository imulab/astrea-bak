package io.imulab.astrea.provider.impl

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.client.assertType
import io.imulab.astrea.crypt.ClientVerificationKeyResolver
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.mustAllBeAcceptedBy
import io.imulab.astrea.domain.extension.mustBeIn
import io.imulab.astrea.domain.extension.requireNotNullOrEmpty
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.error.*
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.provider.AuthorizeProvider
import io.imulab.astrea.spi.http.*
import io.imulab.astrea.spi.json.JsonEncoder
import org.apache.http.client.utils.URIBuilder
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.util.*

class DefaultAuthorizeProvider(private val authorizeHandler: AuthorizeEndpointHandler,
                               private val clientStore: ClientManager,
                               private val httpClient: HttpClient,
                               private val scopeStrategy: ScopeStrategy,
                               private val minStateEntropy: Int = 8,
                               private val clockSkewToleranceSecond: Int = 30,
                               private val expectedAudience: String,
                               private val jsonEncoder: JsonEncoder,
                               private val outputDebugInErrorResponse: Boolean = false) : AuthorizeProvider {

    override fun newAuthorizeRequest(reader: HttpRequestReader): AuthorizeRequest {
        val builder = DefaultAuthorizeRequest.Builder().also {
            it.setId(UUID.randomUUID().toString())
            it.setRequestTime(LocalDateTime.now())
        }

        val form = reader.getForm().also {
            builder.setForm(it)
        }

        val client = clientStore.getClient(form.mustSingleValue(PARAM_CLIENT_ID)).also {
            builder.setClient(it)
        }

        // oidc
        tryParseOidcParameters(builder) // TODO potential improvement of architecture

        reader.getForm().run {
            // redirect_uri
            mustSingleValue(PARAM_REDIRECT_URI)
                    .determineRedirectUri(client.getRedirectUris())
                    .let {
                        it.checkValidRedirectUri()
                        builder.setRedirectUri(it)
                    }

            // scope
            mustSingleValue(PARAM_SCOPE)
                    .requireNotNullOrEmpty(PARAM_SCOPE)
                    .split(SPACE)
                    .filter { it.isNotEmpty() }
                    .mustAllBeAcceptedBy(client.getScopes(), scopeStrategy) { t ->
                        InvalidScopeException.NotAcceptedByClient(t.scope)
                    }
                    .forEach { builder.addScopes(it) }

            // response_type
            mustSingleValue(PARAM_RESPONSE_TYPE)
                    .requireNotNullOrEmpty(PARAM_RESPONSE_TYPE)
                    .split(SPACE)
                    .filter { it.isNotEmpty() }
                    .map { ResponseType.fromSpecValue(it, ignoreCase = false) }
                    .mustBeIn(client.getResponseTypes()) {
                        RequestParameterUnsupportedValueException.ClientResponseType(it.message!!)
                    }
                    .forEach { builder.addResponseTypes(it) }

            // state
            mustSingleValue(PARAM_STATE)
                    .requireNotNullOrEmpty(PARAM_STATE)
                    .let {
                        if (it.length < minStateEntropy)
                            throw RequestParameterInvalidValueException.StateInsufficientEntropy(it, minStateEntropy)
                        builder.setState(it)
                    }
        }

        return builder.build() as AuthorizeRequest
    }

    override fun newAuthorizeResponse(request: AuthorizeRequest, session: Session): AuthorizeResponse {
        val response = DefaultAuthorizeResponse()

        request.setSession(session)
        authorizeHandler.handleAuthorizeRequest(request, response)

        return response
    }

    override fun encodeAuthorizeResponse(writer: HttpResponseWriter, request: AuthorizeRequest, response: AuthorizeResponse) {
        val redirectUri = URIBuilder(request.getRedirectUri()!!).also {
            response.getQueries().forEach { t, u ->
                it.addParameter(t, u[0])
            }
            it.fragment = response.getFragments().entries.joinToString("&") { "${it.key}=${it.value[0]}" }
        }.build().toString()

        response.getHeaders().forEach { t, u ->
            writer.setHeader(t, u[0])
        }

        writer.setHeader("Location", redirectUri)
        writer.setStatus(302)
    }

    override fun encodeAuthorizeError(writer: HttpResponseWriter, request: AuthorizeRequest, error: Throwable) {
        val exception = error as? OAuthException ?: OAuthException.ServerException(error)

        if (!request.isRedirectUriValid()) {
            writer.setStatus(exception.statusCode())
            writer.setHeader("Content-Type", "application/json;charset=UTF-8")
            exception.extraHeaders().forEach(writer::setHeader)
            writer.writeBody(jsonEncoder.encode(exception.toMap(outputDebugInErrorResponse)))
            return
        }

        val redirectUri = URIBuilder(request.getRedirectUri()!!).also { builder ->
            if (request.getResponseTypes().isNotEmpty()
                    && !(request.getResponseTypes().exactly(ResponseType.Code))
                    && !exception.isResponseTypeRelated()
            ) {
                builder.fragment = exception
                        .toMap(outputDebugInErrorResponse)
                        .entries
                        .joinToString("&") { "${it.key}=${it.value}" }
            } else {
                exception
                        .toMap(outputDebugInErrorResponse)
                        .forEach { t, u -> builder.setParameter(t, u) }
            }
        }.build().toString()

        writer.setHeader("Location", redirectUri)
        exception.extraHeaders().forEach(writer::setHeader)
        writer.setStatus(302)
    }

    private fun tryParseOidcParameters(builder: DefaultAuthorizeRequest.Builder) {
        require(builder.form.isNotEmpty())
        requireNotNull(builder.client)

        val form = builder.form

        if (!form.mustSingleValue(PARAM_SCOPE).split(SPACE).contains(SCOPE_OPENID))
            return

        // request, request_uri
        val assertion: String = form.singleValue(PARAM_REQUEST).let {
            val locationOfIt = form.singleValue(PARAM_REQUEST_URI)

            if (it.isBlank()) {
                return@let if (locationOfIt.isBlank()) "" else
                    httpClient.get(locationOfIt).ensureStatus(expected = 200, exceptionEnhancer = { e ->
                        InvalidRequestUriException(locationOfIt, "Received non-200 code ${e.message}.")
                    }).body().toString(StandardCharsets.UTF_8)
            } else {
                return@let if (locationOfIt.isBlank()) it else
                    throw RequestNotSupportedException("Cannot use both '$PARAM_REQUEST' and '$PARAM_REQUEST_URI' parameter in the same request.")
            }
        }
        if (assertion.isBlank())
            return

        // client
        val client = builder.client.assertType<OpenIdConnectClient>().also {
            if (it.getJsonWebKeys() == null && it.getJsonKeyKeysUri().isBlank())
                throw InvalidClientException.JwkNotFound()
        }

        // JWT
        // TODO refactor to jwtRs256 validator
        val jwtConsumer = JwtConsumerBuilder()
                .setJwsAlgorithmConstraints(client.getRequestObjectSigningAlgorithm().toJwsAlgorithmConstraints())
                .setSkipVerificationKeyResolutionOnNone()
                .setVerificationKeyResolver(ClientVerificationKeyResolver(client))
                .setAllowedClockSkewInSeconds(clockSkewToleranceSecond)
                .setExpectedAudience(true, expectedAudience)
                .setExpectedIssuer(true, client.getId())
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .build()
        jwtConsumer.processToClaims(assertion).claimsMap.forEach { k, v ->
            if (k == PARAM_SCOPE) {
                when (v) {
                    is Collection<*> -> v.map { it.toString() }.filter { it.isNotBlank() }.forEach { builder.addScopes(it) }
                    is String -> v.split(SPACE).filter { it.isNotEmpty() }.forEach { builder.addScopes(it) }
                    else -> throw InvalidScopeException(v.toString(), "Scope can only be of list type or string type.")
                }
                builder.setForm(PARAM_SCOPE, builder.scopes.joinToString(separator = SPACE))
            } else {
                builder.setForm(k, v.toString())
            }
        }
    }
}