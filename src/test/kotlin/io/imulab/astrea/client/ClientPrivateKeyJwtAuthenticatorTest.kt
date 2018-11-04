package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientPrivateKeyJwtAuthenticator
import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.AuthMethod
import io.imulab.astrea.domain.JWT_BEARER_CLIENT_ASSERTION_TYPE
import io.imulab.astrea.error.ClientAuthenticationException
import io.imulab.astrea.spi.http.HttpRequestReader
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mindrot.jbcrypt.BCrypt
import org.mockito.Mockito

class ClientPrivateKeyJwtAuthenticatorTest {

    @Test
    fun `registered oidc client perform good request should pass`() {
        val authenticator = ClientPrivateKeyJwtAuthenticator(clientManager, tokenEndpointUrl)
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.formValue("client_id")).thenReturn("foo")
            Mockito.`when`(it.formValue("client_assertion_type"))
                    .thenReturn(JWT_BEARER_CLIENT_ASSERTION_TYPE)
            Mockito.`when`(it.formValue("client_assertion")).thenReturn(
                    JsonWebSignature().also {
                        it.payload = JwtClaims().also {
                            it.setGeneratedJwtId()
                            it.issuer = "foo"
                            it.subject = "foo"
                            it.setAudience(tokenEndpointUrl)
                            it.setIssuedAtToNow()
                            it.setExpirationTimeMinutesInTheFuture(10f)
                        }.toJson()
                        it.keyIdHeaderValue = "test-key"
                        it.key = testJwk.rsaPrivateKey
                        it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
                    }.compactSerialization
            )
        }

        Assertions.assertTrue(authenticator.supports(request))
        Assertions.assertEquals("foo", authenticator.authenticate(request).getId())
    }

    @Test
    fun `registered oidc client perform good request without client_id should still pass`() {
        val authenticator = ClientPrivateKeyJwtAuthenticator(clientManager, tokenEndpointUrl)
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.formValue("client_id")).thenReturn("")
            Mockito.`when`(it.formValue("client_assertion_type"))
                    .thenReturn(JWT_BEARER_CLIENT_ASSERTION_TYPE)
            Mockito.`when`(it.formValue("client_assertion")).thenReturn(
                    JsonWebSignature().also {
                        it.payload = JwtClaims().also {
                            it.setGeneratedJwtId()
                            it.issuer = "foo"
                            it.subject = "foo"
                            it.setAudience(tokenEndpointUrl)
                            it.setIssuedAtToNow()
                            it.setExpirationTimeMinutesInTheFuture(10f)
                        }.toJson()
                        it.keyIdHeaderValue = "test-key"
                        it.key = testJwk.rsaPrivateKey
                        it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
                    }.compactSerialization
            )
        }

        Assertions.assertTrue(authenticator.supports(request))
        Assertions.assertEquals("foo", authenticator.authenticate(request).getId())
    }

    @Test
    fun `mismatched issuer should fail`() {
        val authenticator = ClientPrivateKeyJwtAuthenticator(clientManager, tokenEndpointUrl)
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.formValue("client_id")).thenReturn("")
            Mockito.`when`(it.formValue("client_assertion_type"))
                    .thenReturn(JWT_BEARER_CLIENT_ASSERTION_TYPE)
            Mockito.`when`(it.formValue("client_assertion")).thenReturn(
                    JsonWebSignature().also {
                        it.payload = JwtClaims().also {
                            it.setGeneratedJwtId()
                            it.issuer = "mismatch"
                            it.subject = "foo"
                            it.setAudience(tokenEndpointUrl)
                            it.setIssuedAtToNow()
                            it.setExpirationTimeMinutesInTheFuture(10f)
                        }.toJson()
                        it.keyIdHeaderValue = "test-key"
                        it.key = testJwk.rsaPrivateKey
                        it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
                    }.compactSerialization
            )
        }

        Assertions.assertTrue(authenticator.supports(request))
        Assertions.assertThrows(ClientAuthenticationException::class.java) {
            authenticator.authenticate(request)
        }
    }

    private val tokenEndpointUrl = "https://test.com/oauth/token"

    private val testJwk: RsaJsonWebKey by lazy {
        RsaJwkGenerator.generateJwk(2048).also {
            it.use = Use.SIGNATURE
            it.keyId = "test-key"
        }
    }

    private val clientManager: ClientManager by lazy {
        val mocked = Mockito.mock(ClientManager::class.java)
        Mockito.`when`(mocked.getClient("foo")).thenReturn(DefaultOidcClient(
                oauth = DefaultOAuthClient(
                        id = "foo",
                        secret = BCrypt.hashpw("s3cret", BCrypt.gensalt()).toByteArray()
                ),
                reqObjSignAlg = SigningAlgorithm.RS256,
                tokenEndpointAuth = AuthMethod.PrivateKeyJwt,
                jwk = JsonWebKeySet(testJwk)
        ))

        return@lazy mocked
    }
}