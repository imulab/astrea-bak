package io.imulab.astrea.crypt

import io.imulab.astrea.authorize.AuthorizeCode
import io.imulab.astrea.authorize.AuthorizeCodeStrategy
import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.oauth.OAuthRequest
import io.imulab.astrea.oauth.TokenType
import org.jose4j.jca.ProviderContext
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.HmacUsingShaAlgorithm
import org.jose4j.mac.MacUtil
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.TemporalAmount
import java.util.*
import java.util.concurrent.ThreadLocalRandom
import javax.crypto.SecretKey

class HmacSha256Strategy(
        private val secretKey: SecretKey,
        private val authorizeCodeEntropy: Int = 32,
        private val authorizeCodeLifespan: TemporalAmount = Duration.ofMinutes(10)
) : AuthorizeCodeStrategy {

    private val hmac = HmacUsingShaAlgorithm(
            AlgorithmIdentifiers.HMAC_SHA256,
            MacUtil.HMAC_SHA256,
            256
    )

    private val base64Encoder = Base64.getUrlEncoder().withoutPadding()
    private val base64Decoder = Base64.getUrlDecoder()


    override fun computeAuthorizeCodeSignature(code: String): String {
        return base64Encoder.encodeToString(computeCodeSignatureRaw(base64Decoder.decode(code)))
    }

    private fun computeCodeSignatureRaw(code: ByteArray): ByteArray {
        return hmac.sign(secretKey, code, ProviderContext())
    }

    override fun generateNewAuthorizeCode(request: OAuthRequest): AuthorizeCode {
        val code = ByteArray(authorizeCodeEntropy)
        ThreadLocalRandom.current().nextBytes(code)

        return AuthorizeCode(
                token = base64Encoder.encodeToString(code),
                signature = base64Encoder.encodeToString(computeCodeSignatureRaw(code))
        )
    }

    override fun validateAuthorizeCode(request: OAuthRequest, code: String) {
        if (request.getSession()?.getExpiry(TokenType.AuthorizeCode)
                        ?.isBefore(LocalDateTime.now().plus(authorizeCodeLifespan)) == true) {
            throw InvalidAuthorizeCodeException(code, "expired")
        }

        val authorizeCode = AuthorizeCode.fromCode(code)
        if (!hmac.verifySignature(
                        base64Decoder.decode(authorizeCode.signature),
                        secretKey,
                        base64Decoder.decode(authorizeCode.token),
                        ProviderContext()
                )) {
            throw InvalidAuthorizeCodeException(code, "failed to verify signature")
        }
    }
}