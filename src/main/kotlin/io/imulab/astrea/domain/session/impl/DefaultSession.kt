package io.imulab.astrea.domain.session.impl

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.session.Session
import java.time.LocalDateTime

/**
 * Default implementation of [Session].
 */
open class DefaultSession(private val username: String = "",
                          private val subject: String = "") : Session {

    private val expiryLookup = HashMap<TokenType, LocalDateTime>()

    override fun setExpiry(tokenType: TokenType, expiry: LocalDateTime) {
        this.expiryLookup[tokenType] = expiry
    }

    override fun getExpiry(tokenType: TokenType): LocalDateTime? = this.expiryLookup[tokenType]

    override fun getUsername(): String = this.username

    override fun getSubject(): String = this.subject

    override fun clone(): Session {
        val clone = DefaultSession(this.username, this.subject)

        TokenType.values().forEach { t ->
            val expiry = this.getExpiry(t)
            if (expiry != null) {
                clone.setExpiry(t, expiry)
            }
        }

        return clone
    }

    open class Builder(var username: String? = null,
                       var subject: String? = null,
                       val expiry: MutableMap<TokenType, LocalDateTime> = hashMapOf()) {

        fun setUsername(username: String) = apply { this.username = username }

        fun setSubject(subject: String) = apply { this.subject = subject }

        fun setExpiry(type: TokenType, expiry: LocalDateTime) = apply { this.expiry[type] = expiry }

        open fun build(): Session = DefaultSession(
                username = username ?: "",
                subject = subject ?: ""
        ).also {
            this.expiry.forEach(it::setExpiry)
        }
    }
}