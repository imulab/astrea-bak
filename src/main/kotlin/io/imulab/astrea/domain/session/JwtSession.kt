package io.imulab.astrea.domain.session

import org.jose4j.jwt.JwtClaims

/**
 * An oauth session that uses JWT to preserve state.
 */
interface JwtSession : Session {
    /**
     * Returns the claims for this session.
     */
    fun getJwtClaims(): JwtClaims

    /**
     * Returns the headers of the JWT.
     */
    fun getJwtHeaders(): Map<String, String>
}