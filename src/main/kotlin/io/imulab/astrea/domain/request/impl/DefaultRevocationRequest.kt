package io.imulab.astrea.domain.request.impl

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.RevocationRequest

class DefaultRevocationRequest(
        private var token: String = "",
        private var tokenType: TokenType = TokenType.Unknown,
        private var client: OAuthClient
) : RevocationRequest {

    override fun getToken(): String = token

    override fun getTokenType(): TokenType = tokenType

    override fun getClient(): OAuthClient = client

    class Builder(var token: String = "",
                  var tokenType: TokenType = TokenType.Unknown,
                  var client: OAuthClient? = null) {

        fun build(): RevocationRequest {
            require(token.isNotEmpty())
            requireNotNull(client)
            return DefaultRevocationRequest(token = token, tokenType = tokenType, client = client!!)
        }
    }
}