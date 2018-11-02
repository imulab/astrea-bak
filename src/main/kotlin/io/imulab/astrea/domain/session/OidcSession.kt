package io.imulab.astrea.domain.session

import org.jose4j.jwt.JwtClaims

/**
 * Session for a Open ID Connect request.
 */
interface OidcSession : Session {

    /**
     * Returns the claim in the id_token
     */
    fun getIdTokenClaims(): JwtClaims

    /**
     * Returns the headers in the id_token
     */
    fun getIdTokenHeaders(): Map<String, String>
}