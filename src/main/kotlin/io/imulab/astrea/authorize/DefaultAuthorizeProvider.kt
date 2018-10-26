package io.imulab.astrea.authorize

import io.imulab.astrea.*
import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.jwk.ClientVerificationKeyResolver
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.time.LocalDateTime
import java.util.*

class DefaultAuthorizeProvider(private val clientStore: ClientManager,
                               private val httpClient: HttpClient,
                               private val scopeStrategy: OAuthScopeStrategy,
                               private val minStateEntropy: Int = 8,
                               private val clockSkewToleranceSecond: Int = 30,
                               private val expectedAudience: String) : AuthorizeProvider {

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
        determineRedirectUri(
                reader.formValueUnescaped("redirect_uri"),
                client.getRedirectUris()
        ).also {
            it.checkValidRedirectUri()
            builder.setRedirectUri(it)
        }

        // scope
        reader.formValue("scope").also {
            if (it.isBlank)
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
            if (it.isBlank)
                throw IllegalArgumentException("response_type is mandatory.")
        }.split(" ")
                .filter { it.isNotEmpty() }
                .map { ResponseType.fromSpecValue(it, ignoreCase = false) }
                .filter { claimed -> client.getResponseTypes().contains(claimed) }
                .forEach { verified -> builder.addResponseTypes(verified) }

        // state
        reader.formValue("state").also {
            when {
                it.isBlank -> throw IllegalArgumentException("state is mandatory.")
                it.length < minStateEntropy -> throw IllegalArgumentException("state length must be no less than $minStateEntropy.")
                else -> builder.setState(it)
            }
        }

        return builder.build() as AuthorizeRequest
    }

    override fun newAuthorizeResponse(request: AuthorizeRequest, session: OAuthSession): AuthorizeResponse {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encodeAuthorizeResponse(writer: HttpResponseWriter, request: AuthorizeRequest, response: AuthorizeResponse) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encodeAuthorizeError(writer: HttpResponseWriter, request: AuthorizeRequest, error: Throwable) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
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
        if (assertion.isBlank && location.isBlank)
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
        if (client.getJsonWebKeys() == null && client.getJsonKeyKeysUri().isBlank)
            throw IllegalStateException("OIDC client did not register JWK.")

        // JWT
        val jwtConsumer = JwtConsumerBuilder()
                .setJwsAlgorithmConstraints(client.getRequestObjectSigningAlgorithm().toJwsAlgorithmConstraints())
                .setSkipVerificationKeyResolutionOnNone()
                .setVerificationKeyResolver(ClientVerificationKeyResolver(client, httpClient))
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