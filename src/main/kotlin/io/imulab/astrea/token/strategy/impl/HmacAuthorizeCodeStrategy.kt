package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.error.TokenInvalidity
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy

class HmacAuthorizeCodeStrategy(private val hmac: HmacSha256): AuthorizeCodeStrategy {

    override fun computeAuthorizeCodeSignature(code: String): String {
        val parts = code.split(".")
        return when (parts.size) {
            1 -> hmac.sign(parts[0])
            2 -> parts[1]
            else -> throw InvalidAuthorizeCodeException(TokenInvalidity.BadFormat)
        }
    }

    override fun generateNewAuthorizeCode(request: OAuthRequest): AuthorizeCode {
        val parts = hmac.generate().split(".")
        return AuthorizeCode(
                code = parts[0] + "." + parts[1],
                signature = parts[1]
        )
    }

    override fun validateAuthorizeCode(request: OAuthRequest, code: String) {
        val parts = code.split(".")
        if (parts.size != 2)
            throw InvalidAuthorizeCodeException(TokenInvalidity.BadFormat)

        if (!hmac.validate(parts[0], parts[1]))
            throw InvalidAuthorizeCodeException(TokenInvalidity.BadSignature)
    }
}