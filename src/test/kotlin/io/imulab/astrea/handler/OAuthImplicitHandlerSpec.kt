package io.imulab.astrea.handler

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.getAccessTokenFromFragment
import io.imulab.astrea.domain.extension.getStateFromFragment
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.error.InvalidScopeException
import io.imulab.astrea.error.UnauthorizedClientException
import io.imulab.astrea.handler.flow.OAuthImplicitHandler
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthImplicitHandlerSpec: Spek({

    val memoryStorage = MemoryStorage()
    val handler = OAuthImplicitHandler(
            accessTokenStorage = memoryStorage,
            accessTokenStrategy = TokenSupport.AccessToken.defaultStrategy,
            scopeStrategy = StringEqualityScopeStrategy
    )

    describe("correct flow") {

        it("""
            should correctly issue tokens
        """.trimIndent()) {
            val request = RequestSupport.newAuthorizeRequest(responseTypes = setOf(ResponseType.Token))
            val response = DefaultAuthorizeResponse()

            assertThatCode {
                handler.handleAuthorizeRequest(request, response)
            }.doesNotThrowAnyException()

            assertThat(request.hasAllResponseTypesBeenHandled()).isTrue()
            assertThat(response.getAccessTokenFromFragment()).isNotBlank()
            assertThat(response.getFragments().singleValue(PARAM_TOKEN_TYPE)).isEqualTo(TokenType.Bearer.specValue)
            assertThat(response.getFragments().singleValue(PARAM_EXPIRES_IN).toLong()).isGreaterThan(0)
            assertThat(response.getStateFromFragment()).isNotBlank()
            assertThat(response.getFragments().singleValue(PARAM_SCOPE).split(SPACE)).contains("foo", SCOPE_OFFLINE)
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("failure mode") {
        it("""
            client that does not have right to scope should be rejected
        """.trimIndent()) {
            val request = RequestSupport.newAuthorizeRequest(
                    responseTypes = setOf(ResponseType.Token),
                    scopes = setOf("sudo"))
            val response = DefaultAuthorizeResponse()

            assertThatExceptionOfType(InvalidScopeException.NotAcceptedByClient::class.java)
                    .isThrownBy { handler.handleAuthorizeRequest(request, response) }
        }

        it("""
            client incapable of implicit flow should be rejected
        """.trimIndent()) {
            val request = RequestSupport.newAuthorizeRequest(
                    responseTypes = setOf(ResponseType.Token),
                    client = ClientSupport.foo(grantTypeModifier = { it.remove(GrantType.Implicit) }))
            val response = DefaultAuthorizeResponse()

            assertThatExceptionOfType(UnauthorizedClientException::class.java)
                    .isThrownBy { handler.handleAuthorizeRequest(request, response) }
        }
    }
})