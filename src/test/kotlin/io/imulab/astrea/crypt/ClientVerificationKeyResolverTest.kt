package io.imulab.astrea.crypt

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.DefaultOidcClient
import io.imulab.astrea.spi.HttpClient
import io.imulab.astrea.spi.HttpResponseReader
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class ClientVerificationKeyResolverTest {

    @Test
    fun `should resolve correct key`() {
        val keySet = JsonWebKeySet()
        val keys = listOf("foo", "bar")
                .map { kid ->
                    RsaJwkGenerator.generateJwk(2048).also {
                        it.keyId = kid
                        it.use = Use.SIGNATURE
                    }
                }
        keys.forEach {
            keySet.addJsonWebKey(it)
        }

        val testClient = DefaultOidcClient(oauth = DefaultOAuthClient(id = "", secret = ByteArray(0)),
                jwk = keySet,
                reqObjSignAlg = SigningAlgorithm.RS256)

        keys.forEach { key ->
            val jws = JsonWebSignature().also {
                it.payload = JwtClaims().also {
                    it.issuer = "test"
                }.toJson()
                it.key = key.rsaPrivateKey
                it.keyIdHeaderValue = key.keyId
                it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
            }

            val resolved = ClientVerificationKeyResolver(client = testClient, httpClient = NoOpHttpClient)
                    .resolveKey(jws, null)

            Assertions.assertNotNull(resolved)
            Assertions.assertArrayEquals(key.getRsaPublicKey().encoded, resolved.encoded)
        }
    }

    private object NoOpHttpClient : HttpClient {
        override fun get(url: String): HttpResponseReader {
            throw UnsupportedOperationException()
        }
    }

}