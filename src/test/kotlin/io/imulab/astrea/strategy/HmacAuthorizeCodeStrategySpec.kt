package io.imulab.astrea.strategy

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.support.SessionSupport
import io.imulab.astrea.support.TokenSupport
import org.assertj.core.api.Assertions.*
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.time.LocalDateTime

object HmacAuthorizeCodeStrategySpec : Spek({

    val strategy = TokenSupport.AuthorizeCode.defaultStrategy

    describe("fromRaw") {
        it("""
            generated raw code should be converted to domain properly
        """.trimIndent()) {
            val raw = TokenSupport.AuthorizeCode.new().code
            val parsed = strategy.fromRaw(raw)
            assertThat(parsed.code).isEqualTo(raw)
        }
    }

    describe("verify should succeed") {

        describe("should succeed") {
            it("""
                when code is originally generated from this strategy
            """.trimIndent()) {
                val raw = TokenSupport.AuthorizeCode.new().code
                assertThatCode {
                    strategy.validateAuthorizeCode(code = raw, request = mock(OAuthRequest::class.java))
                }.doesNotThrowAnyException()
            }
        }

        describe("should fail") {
            it("""
                when code is bad
            """.trimIndent()) {
                assertThatExceptionOfType(InvalidGrantException.BadFormat::class.java)
                        .isThrownBy {
                            strategy.validateAuthorizeCode(code = "bad", request = mock(OAuthRequest::class.java))
                        }
            }

            it("""
                when code has expired
            """.trimIndent()) {
                val raw = TokenSupport.AuthorizeCode.new().code
                val req = mock(OAuthRequest::class.java).also {
                    `when`(it.getSession()).thenReturn(SessionSupport.default(expiry = mapOf(
                            TokenType.AuthorizeCode to LocalDateTime.now().minusHours(1)
                    )))
                }

                assertThatExceptionOfType(InvalidGrantException.Expired::class.java)
                        .isThrownBy { strategy.validateAuthorizeCode(code = raw, request = req) }
            }
        }
    }


})