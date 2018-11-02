package io.imulab.astrea.token.strategy

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.IdToken

/**
 * Strategy for Open ID Connect id_token.
 */
interface IdTokenStrategy {

    /**
     * Generate a new Open ID Connect id_token .
     */
    fun generateIdToken(request: OAuthRequest): IdToken
}