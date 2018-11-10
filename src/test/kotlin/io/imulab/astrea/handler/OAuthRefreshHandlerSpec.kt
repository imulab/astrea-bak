package io.imulab.astrea.handler

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.PARAM_REFRESH_TOKEN
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.extension.getRefreshToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.handler.flow.OAuthRefreshHandler
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.jose4j.jwt.JwtClaims
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.time.LocalDateTime

object OAuthRefreshHandlerSpec: Spek({

    val memoryStorage = MemoryStorage()
    val handler = OAuthRefreshHandler(
            accessTokenStrategy = TokenSupport.AccessToken.defaultStrategy,
            refreshTokenStrategy = TokenSupport.RefreshToken.defaultStrategy,
            tokenRevocationStorage = memoryStorage
    )

    describe("correct flow") {
        val flow = Flow()

        beforeGroup {
            memoryStorage.createAccessTokenSession(flow.oldAccessToken, flow.oldAccessRequest)
            memoryStorage.createRefreshTokenSession(flow.oldRefreshToken, flow.oldAccessRequest)
        }

        it("""
            should handle access request
        """.trimIndent()) {
            flow.makeAccessRequest {accessRequest ->
                assertThat(handler.supports(accessRequest)).isTrue()
                assertThatCode {
                    handler.handleAccessRequest(accessRequest)
                }.doesNotThrowAnyException()
            }
        }

        it("""
            should populate access request
        """.trimIndent()) {
            assertThat(flow.accessRequest).isNotNull
            assertThatCode {
                handler.populateAccessResponse(flow.accessRequest!!, flow.accessResponse)
            }.doesNotThrowAnyException()
        }

        it("""
            should have issued new tokens
        """.trimIndent()) {
            assertThat(flow.accessResponse.getAccessToken())
                    .isNotEmpty()
                    .isNotEqualTo(flow.oldAccessToken.token)
            assertThat(flow.accessResponse.getRefreshToken())
                    .isNotEmpty()
                    .isNotEqualTo(flow.oldRefreshToken.token)
        }

        it("""
            should not be able to redeem old tokens again
        """.trimIndent()) {
            flow.makeAccessRequest {accessRequest ->
                assertThat(handler.supports(accessRequest)).isTrue()
                assertThatExceptionOfType(InvalidGrantException.NotFound::class.java)
                        .isThrownBy { handler.handleAccessRequest(accessRequest) }
            }
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("failure modes") {
        val flow = Flow()

        beforeEachTest {
            memoryStorage.createAccessTokenSession(flow.oldAccessToken, flow.oldAccessRequest)
            memoryStorage.createRefreshTokenSession(flow.oldRefreshToken, flow.oldAccessRequest)
        }

        it("""
            invalid refresh token should be rejected
        """.trimIndent()) {
            flow.makeAccessRequest("invalid-refresh-token") { accessRequest ->
                assertThatExceptionOfType(InvalidGrantException::class.java)
                        .isThrownBy { handler.handleAccessRequest(accessRequest) }
            }
        }


        it("""
            a different client other than the token audience making request should be rejected
        """.trimIndent()) {
            flow.makeAccessRequest(client = ClientSupport.bar()) { accessRequest ->
                assertThatExceptionOfType(InvalidGrantException.ClientIdentityMismatch::class.java)
                        .isThrownBy { handler.handleAccessRequest(accessRequest) }
            }
        }

        afterEachTest {
            memoryStorage.clearAll()
        }
    }
}) {

    private class Flow() {

        var accessRequest: AccessRequest? = null
        var accessResponse = DefaultAccessResponse()

        val oldAccessRequest: AccessRequest = RequestSupport.newAccessRequest(
                id = "pre-baked",
                session = DefaultJwtSession(claims = JwtClaims().also { c -> c.setGeneratedJwtId() }).also {
                    it.setExpiry(TokenType.AccessToken, LocalDateTime.now().plusHours(1))
                }
        )

        val oldAccessToken: AccessToken = TokenSupport.AccessToken.new()

        val oldRefreshToken: RefreshToken = TokenSupport.RefreshToken.new()

        fun makeAccessRequest(refreshToken: String = oldRefreshToken.token,
                              client: OAuthClient = ClientSupport.foo(),
                              callback: (AccessRequest) -> Unit) {
            accessRequest = RequestSupport.newAccessRequest(
                    grantTypes = setOf(GrantType.RefreshToken),
                    form = mapOf(
                            PARAM_REFRESH_TOKEN to listOf(refreshToken)
                    ),
                    client = client,
                    session = DefaultJwtSession(claims = JwtClaims().also {
                        it.setGeneratedJwtId()
                    })
            )
            callback(accessRequest!!)
        }
    }
}