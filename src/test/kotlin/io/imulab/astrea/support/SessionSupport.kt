package io.imulab.astrea.support

import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.domain.session.impl.DefaultSession

object SessionSupport {

    fun default(): Session {
        return DefaultSession().also {

        }
    }
}