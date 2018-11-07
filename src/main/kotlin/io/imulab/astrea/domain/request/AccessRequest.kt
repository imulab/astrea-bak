package io.imulab.astrea.domain.request

import io.imulab.astrea.domain.GrantType

/**
 * Context for an OAuth Access Request.
 */
interface AccessRequest : OAuthRequest {

    /**
     * Returns the requested grant types.
     */
    fun getGrantTypes(): List<GrantType>

}