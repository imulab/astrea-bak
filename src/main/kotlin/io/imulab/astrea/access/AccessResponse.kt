package io.imulab.astrea.access

import io.imulab.astrea.oauth.TokenType
import java.time.LocalDateTime

/**
 * Data for an OAuth Access Response.
 */
interface AccessResponse {
    /**
     * Set extra information to the access response.
     */
    fun setExtra(key: String, value: Any)

    /**
     * Returns the extra information by [key].
     */
    fun getExtra(key: String): Any?

    /**
     * Set the expiry of the access response.
     */
    fun setExpiry(expiry: LocalDateTime)

    /**
     * Set the scope of the access response.
     */
    fun setScopes(scopes: List<String>)

    /**
     * Set the mandatory access token.
     */
    fun setAccessToken(token: String)

    /**
     * Set the mandatory token type.
     */
    fun setTokenType(type: TokenType)

    /**
     * Returns the access token.
     */
    fun getAccessToken(): String

    /**
     * Return the token type
     */
    fun getTokenType(): TokenType

    /**
     * Converts the access response to a map.
     */
    fun toMap(): Map<String, Any>
}