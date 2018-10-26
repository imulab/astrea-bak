package io.imulab.astrea.authorize

import io.imulab.astrea.OAuthRequest
import io.imulab.astrea.Request
import io.imulab.astrea.ResponseType

/**
 * Context for the OAuth2 Authorize Endpoint.
 */
interface AuthorizeRequest: OAuthRequest {

    /**
     * Returns requested [ResponseType]
     */
    fun getResponseTypes(): Set<ResponseType>

    /**
     * Returns the requested redirect URI, if any.
     */
    fun getRedirectUri(): String?

    /**
     * Returns true if the requested redirect URI is valid; otherwise returns false.
     *
     * Possible cases of invalidity may include, but not limited to missing client,
     * malformed or black listed.
     */
    fun isRedirectUriValid(): Boolean

    /**
     * Returns the requested entropy state.
     */
    fun getState(): String

    /**
     * Confirm that [responseType] has been properly handled.
     */
    fun setResponseTypeHandled(responseType: ResponseType)

    /**
     * Returns true if all requested [ResponseType] ([getResponseTypes]) has been properly
     * handled. It is achieved by calling [setResponseTypeHandled] on each requested
     * [ResponseType]; otherwise false.
     */
    fun hasAllResponseTypesBeenHandled(): Boolean
}

class DefaultAuthorizeRequest(private val baseRequest: OAuthRequest,
                              private val responseTypes: Set<ResponseType> = emptySet(),
                              private val redirectUri: String?,
                              private val state: String): OAuthRequest by baseRequest, AuthorizeRequest {

    private val handled = mutableSetOf<ResponseType>()

    override fun getResponseTypes(): Set<ResponseType> = this.responseTypes

    override fun getRedirectUri(): String? = this.redirectUri

    override fun isRedirectUriValid(): Boolean {
        try {
            determineRedirectUri(this.redirectUri, this.baseRequest.getClient().getRedirectUris())
                    .checkValidRedirectUri()
        } catch (_: IllegalRedirectUriException) {
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

        fun setState(state: String) = apply { this.state }

        override fun build(): OAuthRequest {
            if (this.state.isNullOrBlank())
                throw IllegalStateException("state must be set.")

            return DefaultAuthorizeRequest(
                    baseRequest = super.build(),
                    responseTypes = this.responseTypes,
                    redirectUri = this.redirectUri,
                    state = this.state!!
            )
        }
    }
}