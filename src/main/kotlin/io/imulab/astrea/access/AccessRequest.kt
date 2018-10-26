package io.imulab.astrea.access

import io.imulab.astrea.GrantType
import io.imulab.astrea.OAuthRequest

/**
 * Context for an OAuth Access Request.
 */
interface AccessRequest : OAuthRequest {

    /**
     * Returns the requested grant types.
     */
    fun getGrantTypes(): List<GrantType>
}