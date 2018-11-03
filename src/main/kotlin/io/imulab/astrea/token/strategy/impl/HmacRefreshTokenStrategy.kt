package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.error.InvalidRefreshTokenException
import io.imulab.astrea.error.TokenInvalidity
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.strategy.RefreshTokenStrategy

class HmacRefreshTokenStrategy(private val hmac: HmacSha256) : RefreshTokenStrategy {

    override fun computeRefreshTokenSignature(token: String): String {
        val parts = token.split(".")
        return when (parts.size) {
            1 -> hmac.sign(parts[0])
            2 -> parts[1]
            else -> throw InvalidRefreshTokenException(TokenInvalidity.BadFormat)
        }
    }

    override fun generateNewRefreshToken(request: OAuthRequest): RefreshToken {
        val parts = hmac.generate().split(".")
        return RefreshToken(
                token = parts[0] + "." + parts[1],
                signature = parts[1]
        )
    }

    override fun validateRefreshToken(request: OAuthRequest, token: String) {
        val parts = token.split(".")
        if (parts.size != 2)
            throw InvalidRefreshTokenException(TokenInvalidity.BadFormat)

        if (!hmac.validate(parts[0], parts[1]))
            throw InvalidRefreshTokenException(TokenInvalidity.BadSignature)
    }
}