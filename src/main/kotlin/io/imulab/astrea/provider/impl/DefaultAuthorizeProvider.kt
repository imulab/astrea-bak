package io.imulab.astrea.provider.impl

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.crypt.ClientVerificationKeyResolver
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.error.Rfc6749Error
import io.imulab.astrea.error.toRfc6749Error
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.provider.AuthorizeProvider
import io.imulab.astrea.spi.http.HttpClient
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.spi.json.JsonEncoder
import org.apache.http.client.utils.URIBuilder
import org.apache.http.client.utils.URLEncodedUtils
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.net.URLEncoder
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

        val form = reader.getForm()
        builder.setForm(form)

        // client
        val client = clientStore.getClient(form.singleValue("client_id"))
        builder.setClient(client)

        // oidc
        tryParseOidcParameters(builder)

        // redirect_uri
        reader.formValueUnescaped("redirect_uri")
                .determineRedirectUri(client.getRedirectUris())
                .also {
                    it.checkValidRedirectUri()
                    builder.setRedirectUri(it)
                }

        // scope
        reader.formValue("scope").also {
            if (it.isBlank())
                throw IllegalArgumentException("scope is mandatory.")
        }.split(" ")
                .filter { it.isNotEmpty() }
                .filter { claimed ->
                    client.getScopes().any { registered ->
                        registered.accepts(claimed, scopeStrategy)
                    }
                }
                .forEach { verified -> builder.addScopes(verified) }

        // response_type
        reader.formValue("response_type").also {
            if (it.isBlank())
                throw IllegalArgumentException("response_type is mandatory.")
        }.split(" ")
                .filter { it.isNotEmpty() }
                .map { ResponseType.fromSpecValue(it, ignoreCase = false) }
                .filter { claimed -> client.getResponseTypes().contains(claimed) }
                .forEach { verified -> builder.addResponseTypes(verified) }

        // state
        reader.formValue("state").also {
            when {
                it.isBlank() -> throw IllegalArgumentException("state is mandatory.")
                it.length < minStateEntropy -> throw IllegalArgumentException("state length must be no less than $minStateEntropy.")
                else -> builder.setState(it)
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
        val rfc6749Error = error.toRfc6749Error()

        if (!request.isRedirectUriValid()) {
            writer.setStatus(rfc6749Error.getStatusCode())
            writer.setHeader("Content-Type", "application/json;charset=UTF-8")
            writer.writeBody(jsonEncoder.encode(rfc6749Error.toMap(outputDebugInErrorResponse)))
            return
        }

        val redirectUri = URIBuilder(request.getRedirectUri()!!).also { builder ->
            if (request.getResponseTypes().isNotEmpty()
                    && !(request.hasSingleResponseTypeOf(ResponseType.Code))
                    && rfc6749Error.error != Rfc6749Error.UnsupportedResponseType
            ) {
                builder.fragment = rfc6749Error
                        .toMap(outputDebugInErrorResponse)
                        .entries
                        .joinToString("&") { "${it.key}=${it.value}" }
            } else {
                rfc6749Error
                        .toMap(outputDebugInErrorResponse)
                        .forEach { t, u -> builder.setParameter(t, u) }
            }
        }.build().toString()

        writer.setHeader("Location", redirectUri)
        writer.setStatus(302)
    }

    private fun tryParseOidcParameters(builder: DefaultAuthorizeRequest.Builder) {
        assert(builder.form.isNotEmpty())
        assert(builder.client != null)

        val form = builder.form
        val scopes = form.singleValue("scope").split(" ")

        if (!scopes.contains("openid"))
            return

        // request, request_uri
        var assertion = form.singleValue("request")
        val location = form.singleValue("request_uri")
        if (assertion.isBlank() && location.isBlank())
            return
        else if (location.isNotBlank()) {
            if (assertion.isNotBlank())
                throw IllegalArgumentException("Only one of 'request' and 'request_uri' may be used at the same time.")

            try {
                val locationResp = httpClient.get(location)
                assertion = locationResp.toString()
            } catch (_: Exception) {
                throw IllegalStateException("Failed to read content at $location.")
            }
        }

        // client
        if (builder.client !is OpenIdConnectClient)
            throw IllegalStateException("Non-OIDC client specifies OIDC context.")
        val client = builder.client!! as OpenIdConnectClient
        if (client.getJsonWebKeys() == null && client.getJsonKeyKeysUri().isBlank())
            throw IllegalStateException("OIDC client did not register JWK.")

        // JWT
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
            if (k == "scope") {
                when (v) {
                    is Collection<*> -> v.map { it.toString() }.filter { it.isNotBlank() }.forEach { builder.addScopes(it) }
                    is String -> v.split(" ").filter { it.isNotEmpty() }.forEach { builder.addScopes(it) }
                    else -> throw IllegalArgumentException("scope in request object can only be list or string")
                }
                builder.setForm("scope", builder.scopes.joinToString(separator = " "))
            } else {
                builder.setForm(k, v.toString())
            }
        }
    }
}