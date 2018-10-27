package io.imulab.astrea.access

import io.imulab.astrea.oauth.GrantType
import io.imulab.astrea.oauth.OAuthRequest

/**
 * Context for an OAuth Access Request.
 */
interface AccessRequest : OAuthRequest {

    /**
     * Returns the requested grant types.
     */
    fun getGrantTypes(): List<GrantType>
}