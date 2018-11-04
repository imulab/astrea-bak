package io.imulab.astrea.domain.response.impl

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.response.AccessResponse
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

class DefaultAccessResponse(private val extra: MutableMap<String, Any> = hashMapOf(),
                            private var accessToken: String = "",
                            private var tokenType: TokenType = TokenType.Unknown) : AccessResponse {

    override fun setExtra(key: String, value: Any) {
        this.extra[key] = value
    }

    override fun getExtra(key: String): Any? = this.extra[key]

    override fun setExpiry(expiry: LocalDateTime) {
        this.extra[PARAM_EXPIRES_IN] = LocalDateTime.now().until(expiry, ChronoUnit.SECONDS)
    }

    override fun setScopes(scopes: List<String>) {
        this.extra[PARAM_SCOPE] = scopes.joinToString(SPACE)
    }

    override fun setAccessToken(token: String) {
        this.accessToken = token
    }

    override fun setTokenType(type: TokenType) {
        this.tokenType = type
    }

    override fun getAccessToken(): String = this.accessToken

    override fun getTokenType(): TokenType = this.tokenType

    override fun toMap(): Map<String, Any> = this.extra.toMutableMap().also {
        it[PARAM_ACCESS_TOKEN] = this.accessToken
        it[PARAM_TOKEN_TYPE] = this.tokenType.specValue
    }.toMap()
}