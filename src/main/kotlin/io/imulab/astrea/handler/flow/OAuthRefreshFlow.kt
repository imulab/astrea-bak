package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.exactly
import io.imulab.astrea.domain.extension.getRefreshToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.error.ClientIdentityMismatchException
import io.imulab.astrea.error.ScopeNotGrantedException
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.TokenRevocationStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.TemporalAmount

class OAuthRefreshFlow(
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val accessTokenStrategy: AccessTokenStrategy,
        private val refreshTokenStrategy: RefreshTokenStrategy,
        private val tokenRevocationStorage: TokenRevocationStorage
) : TokenEndpointHandler {

    override fun handleAccessRequest(request: AccessRequest): Boolean {
        if (!request.getGrantTypes().exactly(GrantType.RefreshToken))
            return false

        request.getClient().mustGrantType(GrantType.RefreshToken)

        val refreshToken = request.getRefreshToken().let {
            refreshTokenStrategy.validateRefreshToken(request, it)
            return@let RefreshToken(token = it, signature = refreshTokenStrategy.computeRefreshTokenSignature(it))
        }

        val originalRequest = tokenRevocationStorage.getRefreshTokenSession(refreshToken, request.getSession()!!)
        if (originalRequest.getGrantedScopes().none { it == "offline" || it == "offline_access" })
            throw ScopeNotGrantedException("offline")

        if (request.getClient().getId() != originalRequest.getClient().getId())
            throw ClientIdentityMismatchException(originalRequest.getClient(), request.getClient())

        request.let {
            it.setSession(originalRequest.getSession()!!.clone())
            it.setRequestScopes(originalRequest.getRequestScopes())
            originalRequest.getGrantedScopes().forEach(it::grantScope)
        }

        request.getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))

        return true
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
        if (!request.getGrantTypes().exactly(GrantType.RefreshToken))
            return false

        val oldRefreshToken = request.getRefreshToken().let { rawToken ->
            RefreshToken(token = rawToken, signature = refreshTokenStrategy.computeRefreshTokenSignature(rawToken))
        }
        val oldRequest = tokenRevocationStorage.getRefreshTokenSession(oldRefreshToken, request.getSession()!!).also { oldReq ->
            tokenRevocationStorage.revokeAccessToken(oldReq.getId())
            tokenRevocationStorage.revokeRefreshToken(oldReq.getId())
        }

        val newAccessToken = accessTokenStrategy.generateNewAccessToken(request)
        val newRefreshToken = refreshTokenStrategy.generateNewRefreshToken(request)
        val requestToStore = request.sanitize(emptyList()).also {
            it.setId(oldRequest.getId())
        }

        tokenRevocationStorage.createAccessTokenSession(newAccessToken, requestToStore)
        tokenRevocationStorage.createRefreshTokenSession(newRefreshToken, requestToStore)

        response.setAccessToken(newAccessToken.token)
        response.setTokenType(TokenType.Bearer)
        response.setExpiry(request.getSession()!!.getExpiry(TokenType.AccessToken)!!)
        response.setScopes(request.getGrantedScopes())
        response.setExtra("refresh_token", newRefreshToken.token)

        return true
    }
}