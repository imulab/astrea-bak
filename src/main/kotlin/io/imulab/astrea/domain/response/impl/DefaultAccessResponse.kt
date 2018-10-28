package io.imulab.astrea.domain.response.impl

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.response.AccessResponse
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

class DefaultAccessResponse(private val extra: MutableMap<String, Any> = hashMapOf(),
                            private var accessToken: String = "",
                            private var tokenType: TokenType = TokenType.Bearer) : AccessResponse {

    override fun setExtra(key: String, value: Any) {
        this.extra[key] = value
    }

    override fun getExtra(key: String): Any? = this.extra[key]

    override fun setExpiry(expiry: LocalDateTime) {
        this.extra["expires_in"] = LocalDateTime.now().until(expiry, ChronoUnit.SECONDS)
    }

    override fun setScopes(scopes: List<String>) {
        this.extra["scope"] = scopes.joinToString(" ")
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
        it["access_token"] = this.accessToken
        it["token_type"] = this.tokenType.specValue
    }.toMap()
}