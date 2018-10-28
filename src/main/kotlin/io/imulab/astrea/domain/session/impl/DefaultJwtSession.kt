package io.imulab.astrea.domain.session.impl

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.session.JwtSession
import io.imulab.astrea.domain.session.Session
import org.jose4j.jwt.JwtClaims

/**
 * Default implementation for [JwtSession].
 */
class DefaultJwtSession(username: String = "",
                        subject: String = "",
                        private val claims: JwtClaims,
                        private val headers: Map<String, String> = emptyMap()) : DefaultSession(username, subject), JwtSession {

    override fun getJwtClaims(): JwtClaims = this.claims

    override fun getJwtHeaders(): Map<String, String> = this.headers

    override fun clone(): Session {
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
                  var headers: MutableMap<String, String> = hashMapOf()) : DefaultSession.Builder() {

        fun getClaims(): JwtClaims = this.claims

        fun setHeader(k: String, v: String) = apply { this.headers[k] = v }

        override fun build(): Session =
                DefaultJwtSession(
                        username = username ?: "",
                        subject = subject ?: "",
                        claims = claims,
                        headers = headers
                ).also {
                    expiry.forEach(it::setExpiry)
                }
    }
}