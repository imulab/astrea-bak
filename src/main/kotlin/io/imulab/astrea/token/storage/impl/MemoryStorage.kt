package io.imulab.astrea.token.storage.impl

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.*
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
class MemoryStorage :
        AuthorizeCodeStorage,
        AccessTokenStorage,
        RefreshTokenStorage,
        TokenRevocationStorage,
        OpenIdConnectRequestStorage,
        PkceSessionStorage {

    // start: AuthorizeCodeStorage -------------------------------------------------------------------------------------

    override fun createAuthorizeCodeSession(code: AuthorizeCode, request: OAuthRequest) {
        this.authorizeCodeMap[code.signature] = AuthorizeCodeSession(
                code = code,
                request = request,
                active = true
        )
    }

    override fun getAuthorizeCodeSession(code: AuthorizeCode): OAuthRequest {
        if (this.authorizeCodeMap.containsKey(code.signature)) {
            val rel = this.authorizeCodeMap[code.signature]!!
            if (!rel.active)
                throw InvalidGrantException.Inactive(code.code)
            else if (rel.request.getSession()?.getExpiry(TokenType.AuthorizeCode)?.isBefore(LocalDateTime.now()) == true)
                throw InvalidGrantException.Expired(code.code)
            else
                return rel.request
        } else {
            throw InvalidGrantException.NotFound(code.code)
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
        val session = AccessTokenSession(
                token = token,
                request = request,
                active = true
        )
        this.accessTokenMap[token.signature] = session
        this.accessTokenToRequestIdMap[request.getId()] = session
    }

    override fun getAccessTokenSession(token: AccessToken): OAuthRequest {
        if (this.accessTokenMap.containsKey(token.signature)) {
            val rel = this.accessTokenMap[token.signature]!!
            if (!rel.active)
                throw InvalidGrantException.Inactive(token.token)
            else if (rel.request.getSession()?.getExpiry(TokenType.AccessToken)?.isBefore(LocalDateTime.now()) == true)
                throw InvalidGrantException.Expired(token.token)
            else
                return rel.request
        } else {
            throw InvalidGrantException.NotFound(token.token)
        }
    }

    override fun deleteAccessTokenSession(token: AccessToken) {
        this.accessTokenMap.remove(token.signature)
    }

    // end: AccessTokenStorage -----------------------------------------------------------------------------------------

    // start: RefreshTokenStorage --------------------------------------------------------------------------------------

    override fun createRefreshTokenSession(token: RefreshToken, request: OAuthRequest) {
        val session = RefreshTokenSession(
                token = token,
                request = request,
                active = true
        )
        this.refreshTokenMap[token.signature] = session
        this.refreshTokenToRequestIdMap[request.getId()] = session
    }

    override fun getRefreshTokenSession(token: RefreshToken): OAuthRequest {
        if (this.refreshTokenMap.containsKey(token.signature)) {
            val rel = this.refreshTokenMap[token.signature]!!
            if (!rel.active)
                throw InvalidGrantException.Inactive(token.token)
            else if (rel.request.getSession()?.getExpiry(TokenType.RefreshToken)?.isBefore(LocalDateTime.now()) == true)
                throw InvalidGrantException.Expired(token.token)
            else
                return rel.request
        } else {
            throw InvalidGrantException.NotFound(token.token)
        }
    }

    override fun deleteRefreshTokenSession(token: RefreshToken) {
        this.refreshTokenMap.remove(token.signature)
    }

    // end: RefreshTokenStorage ----------------------------------------------------------------------------------------

    // start: TokenRevocationStorage -----------------------------------------------------------------------------------

    override fun revokeRefreshToken(requestId: String) {
        if (this.refreshTokenToRequestIdMap.containsKey(requestId)) {
            val session = this.refreshTokenToRequestIdMap[requestId]!!
            this.refreshTokenToRequestIdMap.remove(requestId)
            this.refreshTokenMap.remove(session.token.signature)
        }
    }

    override fun revokeAccessToken(requestId: String) {
        if (this.accessTokenToRequestIdMap.containsKey(requestId)) {
            val session = this.accessTokenToRequestIdMap[requestId]!!
            this.accessTokenToRequestIdMap.remove(requestId)
            this.accessTokenMap.remove(session.token.signature)
        }
    }

    // end: TokenRevocationStorage -------------------------------------------------------------------------------------

    // start: OpenIdConnectRequestStorage ------------------------------------------------------------------------------

    override fun createOidcSession(authorizeCode: AuthorizeCode, request: OAuthRequest) {
        this.authorizeCodeToOidcMap[authorizeCode.code] = request
    }

    override fun getOidcSession(authorizeCode: AuthorizeCode): OAuthRequest {
        return this.authorizeCodeToOidcMap[authorizeCode.code]
                ?: throw InvalidGrantException.NotFound(authorizeCode.code)
    }

    override fun deleteOidcSession(authorizeCode: AuthorizeCode) {
        this.authorizeCodeToOidcMap.remove(authorizeCode.code)
    }

    // end: OpenIdConnectRequestStorage --------------------------------------------------------------------------------

    // start: PkceSessionStorage ---------------------------------------------------------------------------------------

    override fun getPkceSession(authorizeCode: AuthorizeCode): OAuthRequest {
        return this.authorizeCodePkceMap[authorizeCode.signature]
                ?: throw InvalidGrantException.NotFound(authorizeCode.code)
    }

    override fun createPkceSession(authorizeCode: AuthorizeCode, request: OAuthRequest) {
        this.authorizeCodePkceMap[authorizeCode.signature] = request
    }

    override fun deletePkceSession(authorizeCode: AuthorizeCode) {
        this.authorizeCodePkceMap.remove(authorizeCode.signature)
    }

    // end: PkceSessionStorage -----------------------------------------------------------------------------------------

    // start: test utilities -------------------------------------------------------------------------------------------

    fun clearAuthorizeCodes() {
        this.authorizeCodeMap.clear()
        this.authorizeCodeToOidcMap.clear()
        this.authorizeCodePkceMap.clear()
    }

    fun clearAccessTokens() {
        this.accessTokenMap.clear()
        this.accessTokenToRequestIdMap.clear()
    }

    fun clearRefreshTokens() {
        this.refreshTokenMap.clear()
        this.refreshTokenToRequestIdMap.clear()
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

        this.accessTokenToRequestIdMap[this.accessTokenMap[signature]?.request?.getId()]
                ?.request
                ?.getSession()
                ?.setExpiry(TokenType.AccessToken, LocalDateTime.now().minusDays(1))
    }

    fun expireRefreshToken(signature: String) {
        this.refreshTokenMap[signature]
                ?.request
                ?.getSession()
                ?.setExpiry(TokenType.RefreshToken, LocalDateTime.now().minusDays(1))

        this.refreshTokenToRequestIdMap[this.refreshTokenMap[signature]?.request?.getId()]
                ?.request
                ?.getSession()
                ?.setExpiry(TokenType.RefreshToken, LocalDateTime.now().minusDays(1))
    }

    // start: test utilities -------------------------------------------------------------------------------------------

    private val authorizeCodeMap: MutableMap<String, AuthorizeCodeSession> = hashMapOf()
    private val accessTokenMap: MutableMap<String, AccessTokenSession> = hashMapOf()
    private val refreshTokenMap: MutableMap<String, RefreshTokenSession> = hashMapOf()
    private val accessTokenToRequestIdMap: MutableMap<String, AccessTokenSession> = hashMapOf()
    private val refreshTokenToRequestIdMap: MutableMap<String, RefreshTokenSession> = hashMapOf()
    private val authorizeCodeToOidcMap: MutableMap<String, OAuthRequest> = hashMapOf()
    private val authorizeCodePkceMap: MutableMap<String, OAuthRequest> = hashMapOf()

    private class AuthorizeCodeSession(val code: AuthorizeCode, val request: OAuthRequest, var active: Boolean)
    private class AccessTokenSession(val token: AccessToken, val request: OAuthRequest, var active: Boolean)
    private class RefreshTokenSession(val token: RefreshToken, val request: OAuthRequest, var active: Boolean)
}