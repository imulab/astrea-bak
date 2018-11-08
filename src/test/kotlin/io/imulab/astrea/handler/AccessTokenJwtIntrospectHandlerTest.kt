package io.imulab.astrea.handler

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.Scope
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.extension.setScopes
import io.imulab.astrea.domain.request.impl.DefaultIntrospectRequest
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.handler.impl.AccessTokenJwtIntrospectHandler
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito

class AccessTokenJwtIntrospectHandlerTest {

    @Test
    fun `introspect a valid token`() {
        val jwt = generateJwt(listOf("foo", "bar"))

        val r = TestContext.handler.introspectToken(DefaultIntrospectRequest.Builder().also {
            it.token = jwt
            it.tokenType = TokenType.AccessToken
            it.client = Mockito.mock(OAuthClient::class.java)
            it.session = DefaultSession()
        }.build())

        assertTrue(r.isActive())
        assertEquals(TokenType.AccessToken, r.getTokenType())
        assertNotNull(r.getAccessRequest())

        r.getAccessRequest()!!.run {
            assertEquals("test-case", getClient().getId())
            assertTrue(getGrantedScopes().containsAll(listOf("foo", "bar")))
            assertNotNull(getSession())
            assertEquals("tester", getSession()!!.getSubject())
            assertNotNull(getSession()!!.getExpiry(TokenType.AccessToken))
        }
    }

    @Test
    fun `introspect an invalid token`() {
        val jwt = "invalid-jwt"

        val r = TestContext.handler.introspectToken(DefaultIntrospectRequest.Builder().also {
            it.token = jwt
            it.tokenType = TokenType.AccessToken
            it.client = Mockito.mock(OAuthClient::class.java)
            it.session = DefaultSession()
        }.build())

        assertFalse(r.isActive())
        assertNull(r.getAccessRequest())
    }

    private fun generateJwt(scopes: List<Scope>): String {
        return JsonWebSignature().also {
            it.key = TestContext.testJwk.rsaPrivateKey
            it.keyIdHeaderValue = "test-key"
            it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
            it.payload = JwtClaims().also { c ->
                c.setGeneratedJwtId()
                c.setAudience("test-case")
                c.subject = "tester"
                c.setIssuedAtToNow()
                c.setExpirationTimeMinutesInTheFuture(100f)
                c.issuer = "test-issuer"
                c.setScopes(scopes)
            }.toJson()
        }.compactSerialization
    }

    private object TestContext {

        val testJwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.use = Use.SIGNATURE
                it.keyId = "test-key"
            }
        }

        val jwtRs256 = JwtRs256(testJwk)

        val handler = AccessTokenJwtIntrospectHandler(jwtRs256 = jwtRs256, issuer = "test-issuer")
    }
}