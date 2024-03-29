package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.domain.DOT
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import java.time.LocalDateTime

class HmacAuthorizeCodeStrategy(private val hmac: HmacSha256) : AuthorizeCodeStrategy {

    override fun fromRaw(raw: String): AuthorizeCode {
        val parts = raw.split(DOT)
        if (parts.size != 2)
            throw InvalidGrantException.BadFormat(raw)
        return AuthorizeCode(
                code = raw,
                signature = parts[1]
        )
    }

    override fun computeAuthorizeCodeSignature(code: String): String {
        val parts = code.split(DOT)
        return when (parts.size) {
            1 -> hmac.sign(parts[0])
            2 -> parts[1]
            else -> throw InvalidGrantException.BadFormat(code)
        }
    }

    override fun generateNewAuthorizeCode(request: OAuthRequest): AuthorizeCode {
        val parts = hmac.generate().split(DOT)
        return AuthorizeCode(
                code = parts[0] + DOT + parts[1],
                signature = parts[1]
        )
    }

    override fun validateAuthorizeCode(request: OAuthRequest, code: String) {
        if (request.getSession()?.getExpiry(TokenType.AuthorizeCode)?.isBefore(LocalDateTime.now()) == true)
            throw InvalidGrantException.Expired(code)

        val parts = code.split(DOT)
        if (parts.size != 2)
            throw InvalidGrantException.BadFormat(code)

        if (!hmac.validate(parts[0], parts[1]))
            throw InvalidGrantException.BadSignature(code)
    }
}