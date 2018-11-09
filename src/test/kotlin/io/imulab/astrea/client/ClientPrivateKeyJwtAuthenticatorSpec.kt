package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientPrivateKeyJwtAuthenticator
import io.imulab.astrea.domain.*
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.HttpSupport
import io.imulab.astrea.support.TokenSupport
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ClientPrivateKeyJwtAuthenticatorSpec : Spek({

    val tokenEndpointUrl = "https://private-key-jwt-auth.spec/"

    describe("Authenticator should support and pass") {

        it("""
            when registered oidc client presents sound client assertion
        """.trimIndent()) {
            val bar = ClientSupport.bar(isPublic = false,
                    tokenEndpointAuthMethod = AuthMethod.PrivateKeyJwt)
            val authenticator = ClientPrivateKeyJwtAuthenticator(
                    clientManager = ClientSupport.clientManager(bar),
                    tokenEndpointUrl = tokenEndpointUrl)
            val req = HttpSupport.request(forms = mapOf(
                    PARAM_CLIENT_ID to listOf(bar.getId()),
                    PARAM_CLIENT_ASSERTION_TYPE to listOf(JWT_BEARER_CLIENT_ASSERTION_TYPE),
                    PARAM_CLIENT_ASSERTION to listOf(
                            TokenSupport.customJwt(
                                    issuer = bar.getId(),
                                    subject = bar.getId(),
                                    audience = tokenEndpointUrl)
                    )
            ))

            assertThat(authenticator.supports(req)).isTrue()
            assertThat(authenticator.authenticate(req))
                    .extracting { client -> client.getId() }
                    .isEqualTo(bar.getId())
        }

        it("""
            when registered oidc client presents sound client assertion and w/o client_id
        """.trimIndent()) {
            val bar = ClientSupport.bar(isPublic = false,
                    tokenEndpointAuthMethod = AuthMethod.PrivateKeyJwt)
            val authenticator = ClientPrivateKeyJwtAuthenticator(
                    clientManager = ClientSupport.clientManager(bar),
                    tokenEndpointUrl = tokenEndpointUrl)
            val req = HttpSupport.request(forms = mapOf(
                    PARAM_CLIENT_ASSERTION_TYPE to listOf(JWT_BEARER_CLIENT_ASSERTION_TYPE),
                    PARAM_CLIENT_ASSERTION to listOf(
                            TokenSupport.customJwt(
                                    issuer = bar.getId(),
                                    subject = bar.getId(),
                                    audience = tokenEndpointUrl)
                    )
            ))

            assertThat(authenticator.supports(req)).isTrue()
            assertThat(authenticator.authenticate(req))
                    .extracting { client -> client.getId() }
                    .isEqualTo(bar.getId())
        }
    }

    describe("Authenticator should support but fail") {
        it("""
            when registered oidc client presents client assertion with mismatch issuer
        """.trimIndent()) {
            val bar = ClientSupport.bar(isPublic = false,
                    tokenEndpointAuthMethod = AuthMethod.PrivateKeyJwt)
            val authenticator = ClientPrivateKeyJwtAuthenticator(
                    clientManager = ClientSupport.clientManager(bar),
                    tokenEndpointUrl = tokenEndpointUrl)
            val req = HttpSupport.request(forms = mapOf(
                    PARAM_CLIENT_ID to listOf(bar.getId()),
                    PARAM_CLIENT_ASSERTION_TYPE to listOf(JWT_BEARER_CLIENT_ASSERTION_TYPE),
                    PARAM_CLIENT_ASSERTION to listOf(
                            TokenSupport.customJwt(
                                    issuer = "not-bar",
                                    subject = bar.getId(),
                                    audience = tokenEndpointUrl)
                    )
            ))

            assertThat(authenticator.supports(req)).isTrue()
            assertThatThrownBy {
                authenticator.authenticate(req)
            }.isInstanceOf(InvalidClientException.AuthenticationFailed::class.java)
        }
    }
})