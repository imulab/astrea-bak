package io.imulab.astrea.oauth

import org.jose4j.http.Get
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwx.Headers
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
open class DefaultOAuthSession(private val username: String = "",
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

    open class Builder(var username: String? = null,
                       var subject: String? = null,
                       val expiry: MutableMap<TokenType, LocalDateTime> = hashMapOf()) {

        fun setUsername(username: String) = apply { this.username = username }

        fun setSubject(subject: String) = apply { this.subject = subject }

        fun setExpiry(type: TokenType, expiry: LocalDateTime) = apply { this.expiry[type] = expiry }

        open fun build(): OAuthSession = DefaultOAuthSession(
                username = username ?: "",
                subject = subject ?: ""
        ).also {
            this.expiry.forEach(it::setExpiry)
        }
    }
}

/**
 * An oauth session that uses JWT to preserve state.
 */
interface JwtSession : OAuthSession {
    /**
     * Returns the claims for this session.
     */
    fun getJwtClaims(): JwtClaims

    /**
     * Returns the headers of the JWT.
     */
    fun getJwtHeaders(): Map<String, String>
}

/**
 * Default implementation for [JwtSession].
 */
class DefaultJwtSession(username: String = "",
                        subject: String = "",
                        private val claims: JwtClaims,
                        private val headers: Map<String, String> = emptyMap()): DefaultOAuthSession(username, subject), JwtSession {

    override fun getJwtClaims(): JwtClaims = this.claims

    override fun getJwtHeaders(): Map<String, String> = this.headers

    override fun clone(): OAuthSession {
        val zuper = super.clone()
        return DefaultJwtSession(
                username = zuper.getUsername(),
                subject = zuper.getSubject(),
                claims = JwtClaims.parse(this.claims.toJson()),
                headers = this.headers.toMap()
        ).also {
            TokenType.values()
                    .map { Pair(it, zuper.getExpiry(it)) }
                    .filter { it.second != null }
                    .forEach { pair -> it.setExpiry(pair.first, pair.second!!) }
        }
    }

    class Builder(private val claims: JwtClaims = JwtClaims(),
                  var headers: MutableMap<String, String> = hashMapOf()) : DefaultOAuthSession.Builder() {

        fun getClaims(): JwtClaims = this.claims

        fun setHeader(k: String, v: String) = apply { this.headers[k] = v }

        override fun build(): OAuthSession =
                DefaultJwtSession(
                        username = username ?: "",
                        subject =  subject ?: "",
                        claims = claims,
                        headers = headers
                ).also {
                    expiry.forEach(it::setExpiry)
                }
    }
}