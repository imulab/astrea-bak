package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientBearerPreIntrospectionAuthenticator
import io.imulab.astrea.domain.PARAM_TOKEN
import io.imulab.astrea.domain.request.impl.DefaultAccessRequest
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.HttpSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ClientBearerAuthenticatorSpec : Spek({

    val memoryStorage = MemoryStorage()
    val strategy: AccessTokenStrategy = TokenSupport.AccessToken.defaultStrategy
    val authenticator = ClientBearerPreIntrospectionAuthenticator(
            accessTokenStorage = memoryStorage,
            accessTokenStrategy = strategy
    )

    describe("Authenticator should succeed") {
        it("""
            when client has proper authentication
        """.trimIndent()) {
            val properToken = TokenSupport.AccessToken.new().also {
                memoryStorage.createAccessTokenSession(it, DefaultAccessRequest.Builder().also { b ->
                    b.client = ClientSupport.foo()
                }.build())
            }

            assertThat(
                    authenticator.authenticate(HttpSupport.request(
                            headers = mapOf("Authorization" to "Bearer ${properToken.token}")
                    ))
            ).extracting { client ->
                client.getId()
            }.isEqualTo(ClientSupport.foo().getId())
        }

        afterEach {
            memoryStorage.clearAll()
        }
    }

    describe("Authenticator should throw exception") {
        it("""
            when client entailed by authentication and introspection is the same one.
        """.trimIndent()) {
            val token = TokenSupport.AccessToken.new().also {
                memoryStorage.createAccessTokenSession(it, DefaultAccessRequest.Builder().also { b ->
                    b.client = ClientSupport.foo()
                }.build())
            }

            assertThatThrownBy {
                authenticator.authenticate(HttpSupport.request(
                        headers = mapOf("Authorization" to "Bearer ${token.token}"),
                        forms = mapOf(PARAM_TOKEN to listOf(token.token))
                ))
            }.isInstanceOf(InvalidClientException.AuthenticationFailed::class.java)
        }

        it("""
            when token is not in storage
        """.trimIndent()) {
            val tokenNotInStorage = TokenSupport.AccessToken.new()
            val anotherToken = TokenSupport.AccessToken.new()

            assertThatThrownBy {
                authenticator.authenticate(HttpSupport.request(
                        headers = mapOf("Authorization" to "Bearer ${tokenNotInStorage.token}"),
                        forms = mapOf(PARAM_TOKEN to listOf(anotherToken.token))
                ))
            }.isInstanceOf(InvalidClientException.AuthenticationFailed::class.java)
        }

        afterEach {
            memoryStorage.clearAll()
        }
    }
})