package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.error.ClientGrantTypeException
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
        if (!request.hasSingleGrantTypeOfRefreshToken())
            return false

        if (!request.getClient().getGrantTypes().contains(GrantType.RefreshToken))
            throw ClientGrantTypeException(request.getClient(), GrantType.RefreshToken)

        val refreshTokenRaw = request.getRequestForm().singleValue("refresh_token").also {
            refreshTokenStrategy.validateRefreshToken(request, it)
        }
        val refreshToken = RefreshToken(
                token = refreshTokenRaw,
                signature = refreshTokenStrategy.computeRefreshTokenSignature(refreshTokenRaw)
        )

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
        if (!request.hasSingleGrantTypeOfRefreshToken())
            return false

        val oldRefreshToken = request.getRequestForm().singleValue("refresh_token").let { rawToken ->
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

    private fun AccessRequest.hasSingleGrantTypeOfRefreshToken(): Boolean =
            this.getGrantTypes().size == 1 && this.getGrantTypes().contains(GrantType.RefreshToken)
}