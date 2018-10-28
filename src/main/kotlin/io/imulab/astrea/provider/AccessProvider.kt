package io.imulab.astrea.provider

import io.imulab.astrea.spi.HttpRequestReader
import io.imulab.astrea.spi.HttpResponseWriter
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.domain.OAuthSession

/**
 * Sub-interface to [OAuthProvider] in order to provide access request and response related functions.
 *
 * This interface is intended to be employed inside a `/oauth/token` endpoint handler:
 * - [newAccessRequest] helps parse the incoming request into a [AccessRequest].
 * - [newAccessResponse] helps generate a response [AccessResponse].
 * - [encodeAccessResponse] helps render a successful http response.
 * - [encodeAccessError] helps render an error http response.
 *
 * Processing the authorize request may potentially rely on stateful information. For example, the server
 * needs to remember the refresh token issued to the client and know how to deal with it when client comes back
 * to exchange for a new access token. An [OAuthSession] is introduced to encapsulate this stateful information.
 *
 * Because this SDK does not express an opinion on a HTTP library, it utilizes an abstraction over http request and http
 * response to access necessary data from whichever HTTP provider library the user chooses. Users can freely adapt their
 * existing http library to [HttpRequestReader] and [HttpResponseWriter].
 *
 * Note that although this interface provides functions related to the `/oauth/token` endpoint. It is not strictly
 * related to issuing access token / refresh token only. For example, Open ID Connect protocol may piggyback this
 * endpoint and ask for an ID Token as well. Therefore, implementations to this interface shall cover different flows
 * which interacts with the `/oauth/token` endpoint. This is typically provided via implementations to the
 * [TokenEndpointHandler] interface. In this SDK, they are the `*Flow` classes.
 *
 * @see OAuthProvider
 * @see TokenEndpointHandler
 */
interface AccessProvider {

    /**
     * Accepts the incoming http request. Performs preliminary validation on the supplied parameters and parse them
     * into a [AccessRequest], which could be used for later processing.
     *
     * The exceptions thrown by this method shall be regarded as OAuth error, and therefore processed by
     * [encodeAccessError].
     *
     * @param reader an abstraction of the http request that provides interface access to required parameters.
     * @param session stateful session information resumed from request.
     *
     * @return a valid [AccessRequest] to encapsulate request parameters.
     */
    fun newAccessRequest(reader: HttpRequestReader, session: OAuthSession): AccessRequest

    /**
     * Process the [request] parsed in [newAccessRequest].
     *
     * The exceptions thrown by this method shall be regarded as OAuth error, and therefore processed by
     * [encodeAccessError].
     *
     * @param request an [AccessRequest] generated from [newAccessRequest].
     *
     * @return an [AccessResponse] which captures all necessary return data.
     */
    fun newAccessResponse(request: AccessRequest): AccessResponse

    /**
     * Writes the [AccessResponse] generated from [newAccessResponse] as http response.
     *
     * Any exceptions thrown by this method shall be regarded as programming error.
     *
     * @param writer an abstraction of the http response.
     * @param request oauth access request generated from [newAccessRequest], provided as reference.
     * @param response oauth access response generated from [newAccessResponse], provide as data source.
     */
    fun encodeAccessResponse(writer: HttpResponseWriter, request: AccessRequest, response: AccessResponse)

    /**
     * Renders any [Throwable] captured during processing into an OAuth http error response.
     *
     * Any exceptions thrown by this method shall be regarded as programming error.
     *
     * @param writer an abstraction of the http response.
     * @param request oauth access request generated from [newAccessRequest], provided as reference.
     * @param error error captured, provided as data source.
     */
    fun encodeAccessError(writer: HttpResponseWriter, request: AccessRequest, error: Throwable)
}