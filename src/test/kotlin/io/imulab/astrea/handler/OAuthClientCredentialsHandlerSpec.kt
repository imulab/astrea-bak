package io.imulab.astrea.handler

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.getRefreshToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.error.UnauthorizedClientException
import io.imulab.astrea.handler.flow.OAuthClientCredentialsHandler
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthClientCredentialsHandlerSpec : Spek({

    val memoryStorage = MemoryStorage()
    val handler = OAuthClientCredentialsHandler(
            scopeStrategy = StringEqualityScopeStrategy,
            accessTokenStrategy = TokenSupport.AccessToken.defaultStrategy,
            accessTokenStorage = memoryStorage,
            refreshTokenStorage = memoryStorage,
            refreshTokenStrategy = TokenSupport.RefreshToken.defaultStrategy)

    describe("correct flow") {

        lateinit var cachedRequest: AccessRequest

        it("""
            request should be correctly handled
        """.trimIndent()) {
            cachedRequest = RequestSupport.newAccessRequestForClientCredentialsFlow()
            assertThatCode {
                handler.handleAccessRequest(cachedRequest)
            }.doesNotThrowAnyException()
        }

        it("""
            response should be correctly populated
        """.trimIndent()) {
            checkNotNull(cachedRequest)
            val response = DefaultAccessResponse()
            assertThatCode {
                handler.populateAccessResponse(cachedRequest, response)
            }.doesNotThrowAnyException()

            assertThat(response.getAccessToken()).isNotBlank()
            assertThat(response.getTokenType()).isEqualTo(TokenType.Bearer)
            assertThat(response.getExtra(PARAM_SCOPE).toString().split(SPACE)).contains("foo", SCOPE_OFFLINE)
            assertThat(response.getExtra(PARAM_EXPIRES_IN) as Long).isGreaterThan(0)
            assertThat(response.getRefreshToken()).isNotBlank()
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("failure modes") {

        it("""
            client without client_credentials grant type should be rejected
        """.trimIndent()) {
            val request = RequestSupport.newAccessRequestForClientCredentialsFlow(
                    client = ClientSupport.foo(grantTypeModifier = { it.remove(GrantType.ClientCredentials) }))

            assertThatExceptionOfType(UnauthorizedClientException::class.java)
                    .isThrownBy { handler.handleAccessRequest(request) }
        }

        afterEachTest {
            memoryStorage.clearAll()
        }
    }
})