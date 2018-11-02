package io.imulab.astrea.strategy

import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.strategy.impl.HmacAuthorizeCodeStrategy
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import java.time.LocalDateTime
import javax.crypto.KeyGenerator

class HmacAuthorizeCodeStrategyTest {

    /**
     * Test generating authorize code and the verify it.
     */
    @Test
    fun `generated authorize code should be verified successfully`() {
        val strategy = HmacAuthorizeCodeStrategy(hmac = cipher)
        val oauthReq = Mockito.mock(OAuthRequest::class.java)

        strategy.generateNewAuthorizeCode(oauthReq).also {
            Assertions.assertNotNull(it.code)
            Assertions.assertNotNull(it.signature)
        }.also {
            strategy.validateAuthorizeCode(oauthReq, it.code)
        }
    }

    @Test
    fun `authorize code whose value is altered should fail verification`() {
        val strategy = HmacAuthorizeCodeStrategy(hmac = cipher)
        val oauthReq = Mockito.mock(OAuthRequest::class.java)

        Assertions.assertThrows(InvalidAuthorizeCodeException::class.java) {
            strategy.generateNewAuthorizeCode(oauthReq).also {
                strategy.validateAuthorizeCode(oauthReq, AuthorizeCode(
                        code = "x" + it.code,
                        signature = it.signature
                ).code)
            }
        }
    }

    @Test
    fun `authorize code which is expired should fail verification`() {
        val strategy = HmacAuthorizeCodeStrategy(hmac = cipher)

        val session = Mockito.mock(Session::class.java)
        Mockito.`when`(session.getExpiry(TokenType.AuthorizeCode)).thenReturn(LocalDateTime.now().minusDays(1))

        val oauthReq = Mockito.mock(OAuthRequest::class.java)
        Mockito.`when`(oauthReq.getSession()).thenReturn(session)

        Assertions.assertThrows(InvalidAuthorizeCodeException::class.java) {
            strategy.generateNewAuthorizeCode(oauthReq).also {
                strategy.validateAuthorizeCode(oauthReq, it.code)
            }
        }
    }

    private val cipher: HmacSha256 by lazy {
        HmacSha256(secretKey = KeyGenerator.getInstance("AES").generateKey())
    }
}