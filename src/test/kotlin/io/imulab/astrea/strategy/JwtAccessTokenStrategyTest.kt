package io.imulab.astrea.strategy

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.token.strategy.impl.JwtAccessTokenStrategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import java.time.LocalDateTime

class JwtAccessTokenStrategyTest {

    @Test
    fun `generated token should be verified successfully`() {
        val strategy = JwtAccessTokenStrategy(jwtRs256 = cipher, issuer = "test")

        val accessToken = strategy.generateNewAccessToken(createOAuthRequest())

        Assertions.assertTrue(accessToken.token.isNotEmpty())
        Assertions.assertTrue(accessToken.signature.isNotEmpty())
        Assertions.assertTrue(accessToken.token.endsWith(accessToken.signature))

        strategy.validateAccessToken(Mockito.mock(OAuthRequest::class.java), accessToken.token)
    }

    @Test
    fun `token generated by another strategy cannot be validated`() {
        val anotherJwk = RsaJwkGenerator.generateJwk(2048).also {
            it.keyId = "foo"
            it.use = Use.SIGNATURE
        }

        val strategy1 = JwtAccessTokenStrategy(jwtRs256 = cipher, issuer = "test")
        val strategy2 = JwtAccessTokenStrategy(jwtRs256 = JwtRs256(anotherJwk), issuer = "test")

        val accessTokenFromStrategy1 = strategy1.generateNewAccessToken(createOAuthRequest())

        Assertions.assertThrows(InvalidGrantException::class.java) {
            strategy2.validateAccessToken(
                    Mockito.mock(OAuthRequest::class.java),
                    accessTokenFromStrategy1.token
            )
        }
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

    private val rsaJwk: RsaJsonWebKey by lazy {
        RsaJwkGenerator.generateJwk(2048).also {
            it.keyId = "foo"
            it.use = Use.SIGNATURE
        }
    }

    private val cipher: JwtRs256 by lazy { JwtRs256(rsaJwk) }
}