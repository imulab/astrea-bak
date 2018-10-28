package io.imulab.astrea.strategy

import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.OAuthSession
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.token.strategy.impl.HmacSha256Strategy
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable
import org.mockito.Mockito.*
import java.time.Duration
import java.time.LocalDateTime
import javax.crypto.KeyGenerator

class HmacSha256StrategyTest {

    /**
     * Test generating authorize code and the verify it.
     */
    @Test
    fun `generated authorize code should be verified successfully`() {
        val strategy = HmacSha256Strategy(
                secretKey = KeyGenerator.getInstance("AES").generateKey(),
                authorizeCodeEntropy = 32
        )
        val oauthReq = mock(OAuthRequest::class.java)

        strategy.generateNewAuthorizeCode(oauthReq).also {
            assertNotNull(it.token)
            assertNotNull(it.signature)
        }.also {
            strategy.validateAuthorizeCode(oauthReq, it.toString())
        }
    }

    @Test
    fun `authorize code whose value is altered should fail verification`() {
        val strategy = HmacSha256Strategy(
                secretKey = KeyGenerator.getInstance("AES").generateKey(),
                authorizeCodeEntropy = 32
        )
        val oauthReq = mock(OAuthRequest::class.java)
        val shouldFail = Executable {
            strategy.generateNewAuthorizeCode(oauthReq).also {
                strategy.validateAuthorizeCode(oauthReq, AuthorizeCode(
                        token = it.token + "x",
                        signature = it.signature
                ).toString())
            }
        }

        assertThrows(InvalidAuthorizeCodeException::class.java, shouldFail)
    }

    @Test
    fun `authorize code which is expired should fail verification`() {
        val strategy = HmacSha256Strategy(
                secretKey = KeyGenerator.getInstance("AES").generateKey(),
                authorizeCodeLifespan = Duration.ofMinutes(10)
        )

        val session = mock(OAuthSession::class.java)
        `when`(session.getExpiry(TokenType.AuthorizeCode)).thenReturn(LocalDateTime.now().minusDays(1))

        val oauthReq = mock(OAuthRequest::class.java)
        `when`(oauthReq.getSession()).thenReturn(session)

        val shouldFail = Executable {
            strategy.generateNewAuthorizeCode(oauthReq).also {
                strategy.validateAuthorizeCode(oauthReq, it.toString())
            }
        }

        assertThrows(InvalidAuthorizeCodeException::class.java, shouldFail)
    }
}