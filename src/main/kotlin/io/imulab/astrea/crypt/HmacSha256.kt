package io.imulab.astrea.crypt

import org.jose4j.jca.ProviderContext
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.HmacUsingShaAlgorithm
import org.jose4j.mac.MacUtil
import java.util.*
import java.util.concurrent.ThreadLocalRandom
import javax.crypto.SecretKey

/**
 * Cryptography utility to generate HMAC-SHA256 random values and signatures.
 */
class HmacSha256(
        private val entropy: Int = 32,
        private val secretKey: SecretKey,
        private val base64Encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding(),
        private val base64Decoder: Base64.Decoder = Base64.getUrlDecoder()
) {

    private val hmac = HmacUsingShaAlgorithm(
            AlgorithmIdentifiers.HMAC_SHA256,
            MacUtil.HMAC_SHA256,
            256
    )

    /**
     * Generate a random byte array whose size is [entropy]. The returned value is a period delimited
     * two parts string. The first part is the base64 encoded value of the random bytes. The second
     * part is the base64 encoded value of the signature. The format can be read is `$random.$signature`.
     */
    fun generate(): String {
        val bytes = ByteArray(entropy).also {
            ThreadLocalRandom.current().nextBytes(it)
        }
        val signature = signBytes(bytes)

        return base64Encoder.encodeToString(bytes) + "." + base64Encoder.encodeToString(signature)
    }

    /**
     * Generate a base64 encoded signature of the provided base64 encoded [encodedHash].
     */
    fun sign(encodedHash: String): String {
        val bytes = base64Decoder.decode(encodedHash)
        return base64Encoder.encodeToString(signBytes(bytes))
    }

    /**
     * Returns true if the base64 encoded [encodedHash] matches the base64 encoded [encodedSignature]; false otherwise.
     */
    fun validate(encodedHash: String, encodedSignature: String): Boolean {
        return hmac.verifySignature(
                base64Decoder.decode(encodedSignature),
                secretKey,
                base64Decoder.decode(encodedHash),
                ProviderContext()
        )
    }

    private fun signBytes(block: ByteArray): ByteArray {
        return hmac.sign(secretKey, block, ProviderContext())
    }
}