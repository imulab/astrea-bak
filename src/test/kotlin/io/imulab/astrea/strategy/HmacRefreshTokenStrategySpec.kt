package io.imulab.astrea.strategy

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.support.SessionSupport
import io.imulab.astrea.support.TokenSupport
import org.assertj.core.api.Assertions
import org.mockito.Mockito
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.time.LocalDateTime

object HmacRefreshTokenStrategySpec : Spek({

    val strategy = TokenSupport.RefreshToken.defaultStrategy

    describe("fromRaw") {
        it("""
            generated raw token should be converted to domain properly
        """.trimIndent()) {
            val raw = TokenSupport.RefreshToken.new().token
            val parsed = strategy.fromRaw(raw)
            Assertions.assertThat(parsed.token).isEqualTo(raw)
        }
    }

    describe("verify") {

        describe("should succeed") {
            it("""
                when token is originally generated from this strategy
            """.trimIndent()) {
                val raw = TokenSupport.RefreshToken.new().token
                Assertions.assertThatCode {
                    strategy.validateRefreshToken(token = raw, request = Mockito.mock(OAuthRequest::class.java))
                }.doesNotThrowAnyException()
            }
        }

        describe("should fail") {
            it("""
                when token is bad
            """.trimIndent()) {
                Assertions.assertThatExceptionOfType(InvalidGrantException.BadFormat::class.java)
                        .isThrownBy {
                            strategy.validateRefreshToken(token = "bad", request = Mockito.mock(OAuthRequest::class.java))
                        }
            }

            it("""
                when token has expired
            """.trimIndent()) {
                val raw = TokenSupport.RefreshToken.new().token
                val req = Mockito.mock(OAuthRequest::class.java).also {
                    Mockito.`when`(it.getSession()).thenReturn(SessionSupport.default(expiry = mapOf(
                            TokenType.RefreshToken to LocalDateTime.now().minusHours(1)
                    )))
                }

                Assertions.assertThatExceptionOfType(InvalidGrantException.Expired::class.java)
                        .isThrownBy { strategy.validateRefreshToken(token = raw, request = req) }
            }
        }
    }
})