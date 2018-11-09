package io.imulab.astrea.support

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.domain.session.impl.DefaultSession
import java.time.LocalDateTime

object SessionSupport {

    fun default(username: String = "",
                subject: String = "",
                expiry: Map<TokenType, LocalDateTime> = mapOf()): Session {
        return DefaultSession(username, subject).also {
            expiry.forEach { t, u -> it.setExpiry(t, u) }
        }
    }
}