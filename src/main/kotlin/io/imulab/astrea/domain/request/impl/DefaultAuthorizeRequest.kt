package io.imulab.astrea.domain.request

import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.checkValidRedirectUri
import io.imulab.astrea.domain.determineRedirectUri

class DefaultAuthorizeRequest(private val baseRequest: OAuthRequest,
                              private val responseTypes: Set<ResponseType> = emptySet(),
                              private val redirectUri: String?,
                              private val state: String) : OAuthRequest by baseRequest, AuthorizeRequest {

    private val handled = mutableSetOf<ResponseType>()

    override fun getResponseTypes(): Set<ResponseType> = this.responseTypes

    override fun getRedirectUri(): String? = this.redirectUri

    override fun isRedirectUriValid(): Boolean {
        try {
            this.redirectUri
                    .determineRedirectUri(this.baseRequest.getClient().getRedirectUris())
                    .checkValidRedirectUri()
        } catch (_: Throwable) {
            return false
        }

        return true
    }

    override fun getState(): String = this.state

    override fun setResponseTypeHandled(responseType: ResponseType) {
        this.handled.add(responseType)
    }

    override fun hasAllResponseTypesBeenHandled(): Boolean =
            this.handled.containsAll(this.getResponseTypes())

    class Builder(var responseTypes: MutableSet<ResponseType> = mutableSetOf(),
                  var redirectUri: String? = null,
                  var state: String? = null) : Request.Builder() {

        fun addResponseTypes(vararg responseTypes: ResponseType) = apply { this.responseTypes.addAll(responseTypes) }

        fun setRedirectUri(uri: String) = apply { this.redirectUri = uri }

        fun setState(state: String) = apply { this.state = state }

        override fun build(): OAuthRequest {
            requireNotNull(this.state) { "state not set." }
            require(this.state!!.isNotBlank()) { "state set but blank." }

            return DefaultAuthorizeRequest(
                    baseRequest = super.build(),
                    responseTypes = this.responseTypes,
                    redirectUri = this.redirectUri,
                    state = this.state!!
            )
        }
    }
}