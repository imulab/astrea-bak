package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientSecretPostAuthenticator
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.domain.PARAM_CLIENT_ID
import io.imulab.astrea.domain.PARAM_CLIENT_SECRET
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.HttpSupport
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ClientSecretPostAuthenticatorSpec : Spek({
    val foo = ClientSupport.foo()
    val authenticator = ClientSecretPostAuthenticator(
            clientManager = ClientSupport.clientManager(foo),
            passwordEncoder = BCryptPasswordEncoder())

    describe("Authenticator does not support") {
        it("""
            when request of non-POST http method was made
        """.trimIndent()) {
            val req = HttpSupport.request(method = "GET")
            assertThat(authenticator.supports(req)).isFalse()
        }
    }

    describe("Authenticator should support and succeed") {
        it("""
            when requests was made by client with correct credentials
        """.trimIndent()) {
            val req = HttpSupport.request(forms = mapOf(
                    PARAM_CLIENT_ID to listOf(foo.getId()),
                    PARAM_CLIENT_SECRET to listOf(ClientSupport.OPEN_SECRET)
            ))
            assertThat(authenticator.supports(req)).isTrue()
            assertThat(authenticator.authenticate(req))
                    .extracting { client -> client.getId() }
                    .isEqualTo(foo.getId())
        }
    }

    describe("Authenticator should support but fail") {
        it("""
            when requests was made by client with incorrect credentials
        """.trimIndent()) {
            val req = HttpSupport.request(forms = mapOf(
                    PARAM_CLIENT_ID to listOf(foo.getId()),
                    PARAM_CLIENT_SECRET to listOf("bad_secret")
            ))
            assertThat(authenticator.supports(req)).isTrue()
            assertThatThrownBy {
                authenticator.authenticate(req)
            }.isInstanceOf(InvalidClientException.AuthenticationFailed::class.java)
        }
    }
})