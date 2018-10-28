package io.imulab.astrea.strategy

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.token.strategy.impl.JwtRs256Strategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.consumer.InvalidJwtSignatureException
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable
import org.mockito.Mockito
import java.time.LocalDateTime

class JwtRs256StrategyTest {

    @Test
    fun `generated token should be verified successfully`() {
        val keyPair = generateKey()
        val strategy = JwtRs256Strategy(
                issuer = "test",
                jwk = keyPair
        )

        val accessToken = strategy.generateNewAccessToken(createOAuthRequest())

        assertTrue(accessToken.token.isNotEmpty())
        assertTrue(accessToken.signature.isNotEmpty())
        assertTrue(accessToken.token.endsWith(accessToken.signature))

        strategy.validateAccessToken(Mockito.mock(OAuthRequest::class.java), accessToken.token)
    }

    @Test
    fun `token generated by another strategy cannot be validated`() {
        val keyPair1 = generateKey()
        val keyPair2 = generateKey()

        val strategy1 = JwtRs256Strategy(
                issuer = "test",
                jwk = keyPair1
        )
        val strategy2 = JwtRs256Strategy(
                issuer = "test",
                jwk = keyPair2
        )

        val accessTokenFromStrategy1 = strategy1.generateNewAccessToken(createOAuthRequest())
        val shouldFail = Executable {
            strategy2.validateAccessToken(
                    Mockito.mock(OAuthRequest::class.java),
                    accessTokenFromStrategy1.token
            )
        }

        assertThrows(InvalidJwtSignatureException::class.java, shouldFail)
    }

    private fun createOAuthRequest(): OAuthRequest {
        return DefaultAuthorizeRequest.Builder().also {
            it.setSession(DefaultJwtSession.Builder().also {
                it.getClaims().setStringClaim("email", "foo@bar.com")
                it.setExpiry(TokenType.AccessToken, LocalDateTime.now().plusDays(1))
            }.build())
            it.setClient(DefaultOAuthClient(
                    id = "default-test-client",
                    secret = "s3cret".toByteArray()
            ))
            it.addGrantedScopes("email", "read")
            it.state = "1234567890"
        }.build()
    }

    private fun generateKey(): RsaJsonWebKey =
            RsaJwkGenerator.generateJwk(2048).also {
                it.keyId = "foo"
                it.use = Use.SIGNATURE
            }
}