package io.imulab.astrea.authorize

import io.imulab.astrea.OAuthRequest
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
     * Returns true if all requested [ResponseType] ([responseTypes]) has been properly
     * handled. It is achieved by calling [setResponseTypeHandled] on each requested
     * [ResponseType]; otherwise false.
     */
    fun hasAllResponseTypesBeenHandled(): Boolean
}