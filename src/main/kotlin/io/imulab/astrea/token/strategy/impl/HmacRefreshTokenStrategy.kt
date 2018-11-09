package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.domain.DOT
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import java.time.LocalDateTime

class HmacRefreshTokenStrategy(private val hmac: HmacSha256) : RefreshTokenStrategy {

    override fun fromRaw(raw: String): RefreshToken {
        val parts = raw.split(DOT)
        if (parts.size != 2)
            throw InvalidGrantException.BadFormat(raw)
        return RefreshToken(
                token = raw,
                signature = parts[1]
        )
    }

    override fun computeRefreshTokenSignature(token: String): String {
        val parts = token.split(DOT)
        return when (parts.size) {
            1 -> hmac.sign(parts[0])
            2 -> parts[1]
            else -> throw InvalidGrantException.BadFormat(token)
        }
    }

    override fun generateNewRefreshToken(request: OAuthRequest): RefreshToken {
        val parts = hmac.generate().split(DOT)
        return RefreshToken(
                token = parts[0] + DOT + parts[1],
                signature = parts[1]
        )
    }

    override fun validateRefreshToken(request: OAuthRequest, token: String) {
        if (request.getSession()?.getExpiry(TokenType.RefreshToken)?.isBefore(LocalDateTime.now()) == true)
            throw InvalidGrantException.Expired(token)

        val parts = token.split(DOT)
        if (parts.size != 2)
            throw InvalidGrantException.BadFormat(token)

        if (!hmac.validate(parts[0], parts[1]))
            throw InvalidGrantException.BadSignature(token)
    }
}