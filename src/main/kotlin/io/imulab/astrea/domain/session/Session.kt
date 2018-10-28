package io.imulab.astrea.domain.session

import io.imulab.astrea.domain.TokenType
import java.time.LocalDateTime

/**
 * Represents the session data between OAuth2 requests.
 */
interface Session {

    /**
     * Sets the expiration time of a token, which is identified by [tokenType].
     */
    fun setExpiry(tokenType: TokenType, expiry: LocalDateTime)

    /**
     * Returns the expiry time of a token, which is identified by [tokenType].
     */
    fun getExpiry(tokenType: TokenType): LocalDateTime?

    /**
     * Returns the username, if set; otherwise, returns empty string.
     *
     * Only used during token introspection.
     */
    fun getUsername(): String

    /**
     * Returns the subject, if set; otherwise, returns empty string.
     *
     * Only used during token introspection.
     */
    fun getSubject(): String

    /**
     * Returns a new identical session.
     */
    fun clone(): Session
}





