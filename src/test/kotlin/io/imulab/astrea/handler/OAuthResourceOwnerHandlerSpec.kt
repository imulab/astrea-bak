package io.imulab.astrea.handler

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.handler.flow.OAuthResourceOwnerHandler
import io.imulab.astrea.spi.user.UserAuthenticationException
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.support.UserSupport
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.jose4j.jwt.JwtClaims
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthResourceOwnerHandlerSpec : Spek({

    val memoryStorage = MemoryStorage()
    val handler = OAuthResourceOwnerHandler(
            scopeStrategy = StringEqualityScopeStrategy,
            refreshTokenStrategy = TokenSupport.RefreshToken.defaultStrategy,
            accessTokenStrategy = TokenSupport.AccessToken.defaultStrategy,
            accessTokenStorage = memoryStorage,
            refreshTokenStorage = memoryStorage,
            resourceOwnerAuthenticator = UserSupport.authenticator(invalidUsers = listOf("bar", "baz"))
    )

    describe("correct flow") {

        val flow = Flow()

        it("""
            should handle access request
        """.trimIndent()) {
            flow.makeAccessRequest(username = "foo") { accessRequest ->
                assertThat(handler.supports(accessRequest)).isTrue()
                assertThatCode {
                    handler.handleAccessRequest(accessRequest)
                }.doesNotThrowAnyException()
            }
        }

        it("""
            should populate access response
        """.trimIndent()) {
            assertThat(flow.accessRequest).isNotNull
            assertThatCode {
                handler.populateAccessResponse(flow.accessRequest!!, flow.accessResponse)
            }.doesNotThrowAnyException()
        }

        it("""
            should have issued tokens
        """.trimIndent()) {
            flow.accessResponse.run {
                assertThat(getAccessToken()).isNotBlank()
                assertThat(getTokenType()).isEqualTo(TokenType.Bearer)
                assertThat(getExtra(PARAM_SCOPE).toString().split(SPACE)).contains("foo", SCOPE_OFFLINE)
                assertThat(getExtra(PARAM_EXPIRES_IN) as Long).isGreaterThan(0)
            }
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("failure modes") {

        it("""
            user with invalid credentials should be rejected
        """.trimIndent()) {
            val flow = Flow()
            flow.makeAccessRequest(username = "bar") { accessRequest ->
                assertThat(handler.supports(accessRequest)).isTrue()
                assertThatExceptionOfType(UserAuthenticationException::class.java)
                        .isThrownBy { handler.handleAccessRequest(accessRequest) }
            }
        }

        afterEachTest {
            memoryStorage.clearAll()
        }
    }

}) {

    private class Flow {

        var accessRequest: AccessRequest? = null
        var accessResponse: AccessResponse = DefaultAccessResponse()

        fun makeAccessRequest(username: String = "foo", callback: (AccessRequest) -> Unit) {
            accessRequest = RequestSupport.newAccessRequest(
                    grantTypes = setOf(GrantType.Password),
                    session = DefaultJwtSession(claims = JwtClaims().also { it.setGeneratedJwtId() }),
                    form = mapOf(
                            PARAM_USERNAME to listOf(username),
                            PARAM_PASSWORD to listOf(UserSupport.FIXED_PASSWORD)
                    )
            )
            callback(accessRequest!!)
        }
    }
}