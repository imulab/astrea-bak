package io.imulab.astrea.domain.request.impl

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.request.Request

class DefaultAccessRequest(private val baseRequest: OAuthRequest,
                           private val grantTypes: List<GrantType> = emptyList())
    : OAuthRequest by baseRequest, AccessRequest {

    override fun getGrantTypes(): List<GrantType> = grantTypes

    class Builder(private var grantTypes: MutableList<GrantType> = arrayListOf()) : Request.Builder() {

        fun addGrantType(vararg grantTypes: GrantType) {
            this.grantTypes.addAll(grantTypes)
        }

        fun addGrantType(grantTypes: List<GrantType>) {
            this.grantTypes.addAll(grantTypes)
        }

        override fun build(): OAuthRequest {
            return DefaultAccessRequest(
                    baseRequest = super.build(),
                    grantTypes = this.grantTypes
            )
        }
    }
}