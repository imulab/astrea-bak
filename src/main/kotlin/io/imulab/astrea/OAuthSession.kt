package io.imulab.astrea

import java.time.LocalDateTime

/**
 * Represents the session data between OAuth2 requests.
 */
interface OAuthSession {

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
    fun clone(): OAuthSession
}

/**
 * Default implementation of [OAuthSession].
 */
class DefaultOAuthSession(private val username: String = "",
                          private val subject: String = "") : OAuthSession {

    private val expiryLookup = HashMap<TokenType, LocalDateTime>()

    override fun setExpiry(tokenType: TokenType, expiry: LocalDateTime) {
        this.expiryLookup[tokenType] = expiry
    }

    override fun getExpiry(tokenType: TokenType): LocalDateTime? = this.expiryLookup[tokenType]

    override fun getUsername(): String = this.username

    override fun getSubject(): String = this.subject

    override fun clone(): OAuthSession {
        val clone = DefaultOAuthSession(this.username, this.subject)

        TokenType.values().forEach { t ->
            val expiry = this.getExpiry(t)
            if (expiry != null) {
                clone.setExpiry(t, expiry)
            }
        }

        return clone
    }
}