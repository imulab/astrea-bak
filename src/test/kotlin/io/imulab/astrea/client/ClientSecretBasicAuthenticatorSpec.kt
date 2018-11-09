package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientSecretBasicAuthenticator
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.HttpSupport
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ClientSecretBasicAuthenticatorSpec : Spek({

    val foo = ClientSupport.foo()
    val authenticator = ClientSecretBasicAuthenticator(
            clientManager = ClientSupport.clientManager(foo),
            passwordEncoder = BCryptPasswordEncoder()
    )

    describe("Authenticator does not support") {
        it("""
            when request does not provide Authorization header
        """.trimIndent()) {
            val req = HttpSupport.request(headers = mapOf("Authorization" to ""))
            assertThat(authenticator.supports(req)).isFalse()
        }
    }

    describe("Authenticator should support and succeed") {
        it("""
            when client provides correct credentials
        """.trimIndent()) {
            val req = HttpSupport.request(headers = mapOf(
                    "Authorization" to HttpSupport.basicAuthHeader(foo.getId(), ClientSupport.OPEN_SECRET)
            ))
            assertThat(authenticator.supports(req)).isTrue()
            assertThat(authenticator.authenticate(req))
                    .extracting { client -> client.getId() }
                    .isEqualTo(foo.getId())
        }
    }

    describe("Authenticator should support but fail") {
        it("""
            when Authorization header format is bad
        """.trimIndent()) {
            val req = HttpSupport.request(headers = mapOf(
                    "Authorization" to "Basic bad_header"
            ))
            assertThat(authenticator.supports(req)).isTrue()
            assertThatThrownBy {
                authenticator.authenticate(req)
            }.isInstanceOf(InvalidClientException.AuthenticationFailed::class.java)
        }

        it("""
            when client credential is invalid
        """.trimIndent()) {
            val req = HttpSupport.request(headers = mapOf(
                    "Authorization" to HttpSupport.basicAuthHeader(foo.getId(), "bad_secret")
            ))
            assertThat(authenticator.supports(req)).isTrue()
            assertThatThrownBy {
                authenticator.authenticate(req)
            }.isInstanceOf(InvalidClientException.AuthenticationFailed::class.java)
        }
    }
})