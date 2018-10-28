package io.imulab.astrea.token.storage.impl

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.error.InvalidAccessTokenException
import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.error.InvalidRefreshTokenException
import io.imulab.astrea.error.TokenInvalidity
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.storage.AuthorizeCodeStorage
import io.imulab.astrea.token.storage.RefreshTokenStorage
import java.time.LocalDateTime

/**
 * An in memory implementation of all three main storage interfaces: [AuthorizeCodeStorage], [AccessTokenStorage] and
 * [RefreshTokenStorage]. This class is not intended to be used in production and deliberately takes shortcut in
 * implementation. For instance, the underlying in memory storage never actually removes any authorize code entry, but
 * merely marks them as inactive when invalidated. In addition, it is not thread safe, so do not use it in
 * multi-threaded environments.
 *
 * This class is intended to be used in test cases to relieve the burden of excessive mocking.
 */
class MemoryStorage : AuthorizeCodeStorage, AccessTokenStorage, RefreshTokenStorage {

    // start: AuthorizeCodeStorage -------------------------------------------------------------------------------------

    override fun createAuthorizeCodeSession(code: AuthorizeCode, request: OAuthRequest) {
        this.authorizeCodeMap[code.signature] = AuthorizeCodeSession(
                code = code,
                request = request,
                active = true
        )
    }

    override fun getAuthorizeCodeSession(code: AuthorizeCode, session: Session): OAuthRequest {
        if (this.authorizeCodeMap.containsKey(code.signature)) {
            val rel = this.authorizeCodeMap[code.signature]!!
            if (!rel.active)
                throw InvalidAuthorizeCodeException(TokenInvalidity.Inactive)
            else if (rel.request.getSession()?.getExpiry(TokenType.AuthorizeCode)?.isBefore(LocalDateTime.now()) == true)
                throw InvalidAuthorizeCodeException(TokenInvalidity.Expired)
            else
                return rel.request
        } else {
            throw InvalidAuthorizeCodeException(TokenInvalidity.NotFound)
        }
    }

    override fun invalidateAuthorizeCodeSession(code: AuthorizeCode) {
        this.authorizeCodeMap.computeIfPresent(code.signature) { _: String, u: AuthorizeCodeSession ->
            u.also { it.active = false }
        }
    }

    // end: AuthorizeCodeStorage ---------------------------------------------------------------------------------------

    // start: AccessTokenStorage ---------------------------------------------------------------------------------------

    override fun createAccessTokenSession(token: AccessToken, request: OAuthRequest) {
        this.accessTokenMap[token.signature] = AccessTokenSession(
                token = token,
                request = request,
                active = true
        )
    }

    override fun getAccessTokenSession(token: AccessToken, session: Session): OAuthRequest {
        if (this.accessTokenMap.containsKey(token.signature)) {
            val rel = this.accessTokenMap[token.signature]!!
            if (!rel.active)
                throw InvalidAccessTokenException(TokenInvalidity.Inactive)
            else if (rel.request.getSession()?.getExpiry(TokenType.AccessToken)?.isBefore(LocalDateTime.now()) == true)
                throw InvalidAccessTokenException(TokenInvalidity.Expired)
            else
                return rel.request
        } else {
            throw InvalidAccessTokenException(TokenInvalidity.NotFound)
        }
    }

    override fun deleteAccessTokenSession(token: AccessToken) {
        this.accessTokenMap.remove(token.signature)
    }

    // end: AccessTokenStorage -----------------------------------------------------------------------------------------

    // start: RefreshTokenStorage --------------------------------------------------------------------------------------

    override fun createRefreshTokenSession(token: RefreshToken, request: OAuthRequest) {
        this.refreshTokenMap[token.signature] = RefreshTokenSession(
                token = token,
                request = request,
                active = true
        )
    }

    override fun getRefreshTokenSession(token: RefreshToken, session: Session): OAuthRequest {
        if (this.refreshTokenMap.containsKey(token.signature)) {
            val rel = this.refreshTokenMap[token.signature]!!
            if (!rel.active)
                throw InvalidRefreshTokenException(TokenInvalidity.Inactive)
            else if (rel.request.getSession()?.getExpiry(TokenType.RefreshToken)?.isBefore(LocalDateTime.now()) == true)
                throw InvalidRefreshTokenException(TokenInvalidity.Expired)
            else
                return rel.request
        } else {
            throw InvalidRefreshTokenException(TokenInvalidity.NotFound)
        }
    }

    override fun deleteRefreshTokenSession(token: RefreshToken) {
        this.refreshTokenMap.remove(token.signature)
    }

    // end: RefreshTokenStorage ----------------------------------------------------------------------------------------

    // start: test utilities -------------------------------------------------------------------------------------------

    fun clearAuthorizeCodes() {
        this.authorizeCodeMap.clear()
    }

    fun clearAccessTokens() {
        this.accessTokenMap.clear()
    }

    fun clearRefreshTokens() {
        this.refreshTokenMap.clear()
    }

    fun clearAll() {
        clearAuthorizeCodes()
        clearAccessTokens()
        clearRefreshTokens()
    }

    fun expireAuthorizeCode(signature: String) {
        this.authorizeCodeMap[signature]
                ?.request
                ?.getSession()
                ?.setExpiry(TokenType.AuthorizeCode, LocalDateTime.now().minusDays(1))
    }

    fun expireAccessToken(signature: String) {
        this.accessTokenMap[signature]
                ?.request
                ?.getSession()
                ?.setExpiry(TokenType.AccessToken, LocalDateTime.now().minusDays(1))
    }

    fun expireRefreshToken(signature: String) {
        this.refreshTokenMap[signature]
                ?.request
                ?.getSession()
                ?.setExpiry(TokenType.RefreshToken, LocalDateTime.now().minusDays(1))
    }

    // start: test utilities -------------------------------------------------------------------------------------------

    private val authorizeCodeMap: MutableMap<String, AuthorizeCodeSession> = hashMapOf()
    private val accessTokenMap: MutableMap<String, AccessTokenSession> = hashMapOf()
    private val refreshTokenMap: MutableMap<String, RefreshTokenSession> = hashMapOf()

    private class AuthorizeCodeSession(val code: AuthorizeCode, val request: OAuthRequest, var active: Boolean)
    private class AccessTokenSession(val token: AccessToken, val request: OAuthRequest, var active: Boolean)
    private class RefreshTokenSession(val token: RefreshToken, val request: OAuthRequest, var active: Boolean)
}