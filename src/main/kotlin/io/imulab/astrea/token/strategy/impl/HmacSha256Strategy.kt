package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.error.InvalidAccessTokenException
import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.error.InvalidRefreshTokenException
import io.imulab.astrea.error.TokenInvalidity
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import org.jose4j.jca.ProviderContext
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.HmacUsingShaAlgorithm
import org.jose4j.mac.MacUtil
import java.time.LocalDateTime
import java.util.*
import java.util.concurrent.ThreadLocalRandom
import javax.crypto.SecretKey

class HmacSha256Strategy(
        private val secretKey: SecretKey,
        private val authorizeCodeEntropy: Int = 32,
        private val accessTokenEntropy: Int = 64,
        private val refreshTokenEntropy: Int = 32
) : AuthorizeCodeStrategy, AccessTokenStrategy, RefreshTokenStrategy {

    private val hmac = HmacUsingShaAlgorithm(
            AlgorithmIdentifiers.HMAC_SHA256,
            MacUtil.HMAC_SHA256,
            256
    )

    private val base64Encoder = Base64.getUrlEncoder().withoutPadding()
    private val base64Decoder = Base64.getUrlDecoder()

    // start: AuthorizeCodeStrategy ------------------------------------------------------------------------------------

    override fun computeAuthorizeCodeSignature(code: String): String {
        if (code.isBlank())
            throw InvalidAuthorizeCodeException(TokenInvalidity.BadFormat)

        val parts = code.split(".")
        return when {
            parts.size <= 2 -> base64Encoder.encodeToString(doSign(base64Decoder.decode(parts[0])))
            else -> throw InvalidAuthorizeCodeException(TokenInvalidity.BadFormat, authorizeCodeFormatInstruction)
        }
    }

    override fun generateNewAuthorizeCode(request: OAuthRequest): AuthorizeCode {
        val code = ByteArray(authorizeCodeEntropy)
        ThreadLocalRandom.current().nextBytes(code)

        val signature = base64Encoder.encodeToString(doSign(code))

        return AuthorizeCode(
                code = base64Encoder.encodeToString(code) + "." + signature,
                signature = signature
        )
    }

    override fun validateAuthorizeCode(request: OAuthRequest, code: String) {
        val invalidity = doValidate(TokenType.AuthorizeCode, code, request)
        if (invalidity != null)
            throw InvalidAuthorizeCodeException(invalidity)
    }

    // end: AuthorizeCodeStrategy --------------------------------------------------------------------------------------

    // start: AccessTokenStrategy --------------------------------------------------------------------------------------

    override fun computeAccessTokenSignature(token: String): String {
        if (token.isBlank())
            throw InvalidAccessTokenException(TokenInvalidity.BadFormat, "blank")

        val parts = token.split(".")
        return when {
            parts.size <= 2 -> base64Encoder.encodeToString(doSign(base64Decoder.decode(parts[0])))
            else -> throw InvalidAccessTokenException(TokenInvalidity.BadFormat, accessTokenFormatInstruction)
        }
    }

    override fun generateNewAccessToken(request: OAuthRequest): AccessToken {
        val token = ByteArray(accessTokenEntropy)
        ThreadLocalRandom.current().nextBytes(token)

        val signature = base64Encoder.encodeToString(doSign(token))
        return AccessToken(
                token = base64Encoder.encodeToString(token) + "." + signature,
                signature = signature
        )
    }

    override fun validateAccessToken(request: OAuthRequest, token: String) {
        val invalidity = doValidate(TokenType.AccessToken, token, request)
        if (invalidity != null)
            throw InvalidAccessTokenException(invalidity)
    }

    // end: AccessTokenStrategy ----------------------------------------------------------------------------------------

    // start: RefreshTokenStrategy -------------------------------------------------------------------------------------

    override fun computeRefreshTokenSignature(token: String): String {
        if (token.isBlank())
            throw InvalidRefreshTokenException(TokenInvalidity.BadFormat, "blank")

        val parts = token.split(".")
        return when {
            parts.size <= 2 -> base64Encoder.encodeToString(doSign(base64Decoder.decode(parts[0])))
            else -> throw InvalidRefreshTokenException(TokenInvalidity.BadFormat, refreshTokenFormatInstruction)
        }
    }

    override fun generateNewRefreshToken(request: OAuthRequest): RefreshToken {
        val token = ByteArray(refreshTokenEntropy)
        ThreadLocalRandom.current().nextBytes(token)

        val signature = base64Encoder.encodeToString(doSign(token))
        return RefreshToken(
                token = base64Encoder.encodeToString(token) + "." + signature,
                signature = signature
        )
    }

    override fun validateRefreshToken(request: OAuthRequest, token: String) {
        val invalidity = doValidate(TokenType.RefreshToken, token, request)
        if (invalidity != null)
            throw InvalidRefreshTokenException(invalidity)
    }

    // end: RefreshTokenStrategy ---------------------------------------------------------------------------------------

    // private: --------------------------------------------------------------------------------------------------------

    private fun getFirstPart(token: String): String =
            if (token.contains(".")) token.split(".")[0] else token

    private fun doSign(code: ByteArray): ByteArray {
        return hmac.sign(secretKey, code, ProviderContext())
    }

    private fun doValidate(tokenType: TokenType, token: String, request: OAuthRequest): TokenInvalidity? {
        if (request.getSession()?.getExpiry(tokenType)?.isBefore(LocalDateTime.now()) == true)
            return TokenInvalidity.Expired

        val parts = token.split(".")
        if (parts.size != 2)
            return TokenInvalidity.BadFormat

        if (!hmac.verifySignature(
                        base64Decoder.decode(parts[1]),
                        secretKey,
                        base64Decoder.decode(parts[0]),
                        ProviderContext()
                ))
            return TokenInvalidity.BadSignature

        return null
    }

    companion object {
        const val authorizeCodeFormatInstruction: String = "Proper access code should have two parts, delimited by a \".(dot)\"."
        const val refreshTokenFormatInstruction: String = "Proper refresh token should have two parts, delimited by a \".(dot)\"."
        const val accessTokenFormatInstruction: String = "Proper access token should have two parts, delimited by a \".(dot)\"."
    }
}