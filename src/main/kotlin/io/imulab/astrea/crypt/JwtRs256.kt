package io.imulab.astrea.crypt

import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.consumer.JwtContext

class JwtRs256(private val jwk: RsaJsonWebKey) {

    /**
     * Generate a new JWT token based on the given [claims] and [extraHeaders]. This method
     * only sets the key id (kid) and algorithm (alg) header value and does not other extra
     * processing. The caller must ensure all data has already been provided.
     */
    fun generate(claims: JwtClaims, extraHeaders: Map<String, String>): String {
        val jws = JsonWebSignature()

        extraHeaders.forEach(jws::setHeader)

        jws.also {
            it.payload = claims.toJson()
            it.key = jwk.rsaPrivateKey
            it.keyIdHeaderValue = jwk.keyId
            it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
        }

        return jws.compactSerialization
    }

    /**
     * Decode the given [jwt]. By default, only algorithm constraint is set to decode the JWT.
     * Callers can provide extra [extraCriteria] to enhance the process so it will throw
     * exceptions on invalid tokens. Returns the [JwtContext] as the result of decoding.
     */
    fun decode(jwt: String, extraCriteria: (JwtConsumerBuilder) -> Unit = {}): JwtContext {
        val consumer = JwtConsumerBuilder()
                .setRequireJwtId()
                .setJwsAlgorithmConstraints(SigningAlgorithm.RS256.toJwsAlgorithmConstraints())
                .setVerificationKey(this.jwk.getRsaPublicKey())
                .also(extraCriteria)
                .build()
        return consumer.process(jwt)
    }

    /**
     * Validate the given [jwt]. By default, no other fields besides algorithm will
     * be validated. Caller can provide [extraCriteria] to enhance the validation.
     * Returns a [Throwable] if any exception occurs; otherwise null.
     */
    fun validate(jwt: String, extraCriteria: (JwtConsumerBuilder) -> Unit = {}): Throwable? {
        AlgorithmIdentifiers.RSA_USING_SHA256

        return try {
            decode(jwt, extraCriteria); null
        } catch (t: Throwable) {
            t
        }
    }
}