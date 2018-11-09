package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientNoneAuthenticator
import io.imulab.astrea.domain.AuthMethod
import io.imulab.astrea.domain.PARAM_CLIENT_ID
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.HttpSupport
import org.assertj.core.api.Assertions.*
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ClientNoneAuthenticatorSpec : Spek({

    describe("Authenticator is supported and should succeed") {

        it("""
            when a public oauth client authenticates
        """.trimIndent()) {
            val foo = ClientSupport.foo(isPublic = true)
            val authenticator = ClientNoneAuthenticator(clientManager = ClientSupport.clientManager(foo))
            val req = HttpSupport.request(
                    forms = mapOf(PARAM_CLIENT_ID to listOf(foo.getId()))
            )

            assertThat(authenticator.supports(req)).isTrue()
            assertThat(authenticator.authenticate(req))
                    .extracting { client -> client.getId() }
                    .isEqualTo(foo.getId())
        }

        it ("""
            when a public oidc client with auth_method=none authenticates
        """.trimIndent()) {
            val bar = ClientSupport.bar(isPublic = true, tokenEndpointAuthMethod = AuthMethod.None)
            val authenticator = ClientNoneAuthenticator(clientManager = ClientSupport.clientManager(bar))
            val req = HttpSupport.request(
                    forms = mapOf(PARAM_CLIENT_ID to listOf(bar.getId()))
            )

            assertThat(authenticator.supports(req)).isTrue()
            assertThat(authenticator.authenticate(req))
                    .extracting { client -> client.getId() }
                    .isEqualTo(bar.getId())
        }
    }

    describe("Authenticator is not supported") {
        it("""
            when non-public oauth client authenticates
        """.trimIndent()) {
            val foo = ClientSupport.foo(isPublic = false)
            val authenticator = ClientNoneAuthenticator(clientManager = ClientSupport.clientManager(foo))
            val req = HttpSupport.request(
                    forms = mapOf(PARAM_CLIENT_ID to listOf(foo.getId()))
            )

            assertThat(authenticator.supports(req)).isFalse()
        }
    }
})