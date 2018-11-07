package io.imulab.astrea.domain.response.impl

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.IntrospectResponse

class DefaultIntrospectResponse(
        private val active: Boolean = false,
        private var accessRequest: AccessRequest? = null,
        private var tokenType: TokenType = TokenType.Unknown
) : IntrospectResponse {

    override fun isActive(): Boolean = active

    override fun getAccessRequest(): AccessRequest? = accessRequest

    override fun getTokenType(): TokenType = tokenType
}