package io.imulab.astrea.handler.revoke

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.RevocationRequest
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.handler.RevocationEndpointHandler
import io.imulab.astrea.token.storage.RefreshTokenStorage
import io.imulab.astrea.token.storage.TokenRevocationStorage
import io.imulab.astrea.token.strategy.RefreshTokenStrategy

class RefreshTokenStorageRevocationHandler(
        private val refreshTokenStrategy: RefreshTokenStrategy,
        private val refreshTokenStorage: RefreshTokenStorage,
        private val tokenRevocationStorage: TokenRevocationStorage
) : RevocationEndpointHandler {

    override fun supports(tokenType: TokenType): Boolean =
            tokenType == TokenType.RefreshToken || tokenType == TokenType.Unknown

    override fun revokeToken(request: RevocationRequest): Boolean {
        return try {
            request.getToken()
                    .let { refreshTokenStrategy.fromRaw(it) }
                    .let { refreshTokenStorage.getRefreshTokenSession(it, DefaultSession()) }
                    .let {
                        if (it.getClient().getId() != request.getClient().getId())
                            throw InvalidGrantException.ClientIdentityMismatch(request.getToken())
                        return@let it
                    }
                    .let {
                        tokenRevocationStorage.revokeAccessToken(it.getId())
                        tokenRevocationStorage.revokeRefreshToken(it.getId())
                    }
                    .let { true }
        } catch (e: Exception) {
            if (e is InvalidGrantException.ClientIdentityMismatch)
                throw e
            false
        }
    }
}