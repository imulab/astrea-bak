package io.imulab.astrea.domain.session.impl

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.session.JwtSession
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.Session
import org.jose4j.jwt.JwtClaims
import java.time.LocalDateTime

/**
 * Default implementation of [OidcSession].
 *
 * Since [OidcSession] as basically identical to [JwtSession] with only a semantic difference of claims
 * and headers not indicates those of the id_token. We embed a [jwtSession] here and delegate all methods
 * to it.
 */
class DefaultOidcSession(private val jwtSession: JwtSession) : JwtSession by jwtSession, OidcSession {

    override fun getIdTokenClaims(): JwtClaims = jwtSession.getJwtClaims()

    override fun getIdTokenHeaders(): Map<String, String> = jwtSession.getJwtHeaders()

    override fun clone(): Session = DefaultOidcSession(this.jwtSession.clone() as JwtSession)

    class Builder(
            private val jwtSessionBuilder: DefaultJwtSession.Builder = DefaultJwtSession.Builder()
    ) : DefaultSession.Builder() {

        override fun setUsername(username: String) = apply {
            this.jwtSessionBuilder.setUsername(username)
        }

        override fun setSubject(subject: String) = apply {
            this.jwtSessionBuilder.setSubject(subject)
        }

        override fun setExpiry(type: TokenType, expiry: LocalDateTime) = apply {
            this.jwtSessionBuilder.setExpiry(type, expiry)
        }

        fun getClaims(): JwtClaims = jwtSessionBuilder.getClaims()

        fun setHeader(k: String, v: String) = apply { this.jwtSessionBuilder.headers[k] = v }

        override fun build(): Session = DefaultOidcSession(jwtSessionBuilder.build() as JwtSession)
    }
}