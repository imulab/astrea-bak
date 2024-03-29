package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.containsNone
import io.imulab.astrea.domain.extension.getRefreshToken
import io.imulab.astrea.domain.extension.setRefreshToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.TokenRevocationStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.TemporalAmount

class OAuthRefreshHandler(
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val accessTokenStrategy: AccessTokenStrategy,
        private val refreshTokenStrategy: RefreshTokenStrategy,
        private val tokenRevocationStorage: TokenRevocationStorage
) : TokenEndpointHandler {

    override fun supports(request: AccessRequest): Boolean =
            request.getGrantTypes().exactly(GrantType.RefreshToken)

    override fun handleAccessRequest(request: AccessRequest) {
        if (!supports(request))
            return

        requireNotNull(request.getSession()) { "session must not be null." }

        request.getClient().mustGrantType(GrantType.RefreshToken)

        val refreshToken = request.getRefreshToken().let {
            refreshTokenStrategy.validateRefreshToken(request, it)
            return@let RefreshToken(token = it, signature = refreshTokenStrategy.computeRefreshTokenSignature(it))
        }

        val originalRequest = tokenRevocationStorage.getRefreshTokenSession(refreshToken).also {
            if (it.getGrantedScopes().containsNone(SCOPE_OFFLINE, SCOPE_OFFLINE_ACCESS))
                throw InvalidGrantException.NoOfflineAccess(refreshToken.token)
            if (request.getClient().getId() != it.getClient().getId())
                throw InvalidGrantException.ClientIdentityMismatch(refreshToken.token)
        }

        request.run {
            setSession(originalRequest.getSession()!!.clone())
            setRequestScopes(originalRequest.getRequestScopes())
            originalRequest.getGrantedScopes().forEach(this::grantScope)
            getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))
        }
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {
        if (!supports(request))
            return

        requireNotNull(request.getSession()) { "session must not be null." }

        val oldRefreshToken = refreshTokenStrategy.fromRaw(request.getRefreshToken())
        val oldRequest = tokenRevocationStorage.getRefreshTokenSession(oldRefreshToken).also {
            tokenRevocationStorage.revokeAccessToken(it.getId())
            tokenRevocationStorage.revokeRefreshToken(it.getId())
        }

        val newAccessToken = accessTokenStrategy.generateNewAccessToken(request)
        val newRefreshToken = refreshTokenStrategy.generateNewRefreshToken(request)
        val requestToStore = request.sanitize(emptyList()).also {
            it.setId(oldRequest.getId())
        }

        tokenRevocationStorage.createAccessTokenSession(newAccessToken, requestToStore)
        tokenRevocationStorage.createRefreshTokenSession(newRefreshToken, requestToStore)

        response.run {
            setAccessToken(newAccessToken.token)
            setTokenType(TokenType.Bearer)
            setExpiry(request.getSession()!!.getExpiry(TokenType.AccessToken)!!)
            setScopes(request.getGrantedScopes())
            setRefreshToken(newRefreshToken.token)
        }
    }
}