package io.imulab.astrea.provider

import io.imulab.astrea.HttpRequestReader
import io.imulab.astrea.HttpResponseWriter
import io.imulab.astrea.authorize.AuthorizeRequest
import io.imulab.astrea.authorize.AuthorizeResponse
import io.imulab.astrea.oauth.OAuthSession
import io.imulab.astrea.handler.AuthorizeEndpointHandler

/**
 * Sub-interface to [OAuthProvider] in order to provide authorize request and response related functions.
 *
 * This interface is intended to be employed inside a `/oauth/authorize` endpoint handler:
 * - [newAuthorizeRequest] helps parses the incoming request into a [AuthorizeRequest].
 * - [newAuthorizeResponse] helps generate a [AuthorizeResponse].
 * - [encodeAuthorizeResponse] helps render a successful http response.
 * - [encodeAuthorizeError] helps render an error http response.
 *
 * Processing the authorize request may potentially rely on stateful information. For example, the server
 * needs to remember the authorization code issued to the client and know how to deal with it when client comes back
 * with the code. An [OAuthSession] is introduced to encapsulate this stateful information.
 *
 * Because this SDK does not express an opinion on a HTTP library, it utilizes an abstraction over http request and http
 * response to access necessary data from whichever HTTP provider library the user chooses. Users can freely adapt their
 * existing http library to [HttpRequestReader] and [HttpResponseWriter].
 *
 * Note that although this interface provides functions related to the `/oauth/authorize` endpoint. It is not strictly
 * related to issuing an authorization code. For example, in an implicit flow, a registered client may exchange its
 * credentials directly for an access token at the `/oauth/authorize` endpoint. These scenarios are abstracted by this
 * interface as well. Therefore, implementations to this interface shall look to cover parts of different OAuth defined
 * flows which interact with the `/oauth/authorize` endpoint. This is typically provided via implementations to the
 * [AuthorizeEndpointHandler] interface. In this SDK, they are the `*Flow` classes.
 *
 * @see OAuthProvider
 * @see AuthorizeEndpointHandler
 */
interface AuthorizeProvider {

    /**
     * Accepts the incoming http request. Performs preliminary validation on the supplied parameters and parse them
     * into a [AuthorizeRequest], which could be used for later processing.
     *
     * The exceptions thrown by this method shall be regarded as OAuth error, and therefore processed by
     * [encodeAuthorizeError].
     *
     * @param reader an abstraction of the http request that provides interface access to required parameters.
     *
     * @return a valid [AuthorizeRequest] to encapsulate request parameters.
     */
    fun newAuthorizeRequest(reader: HttpRequestReader): AuthorizeRequest

    /**
     * Process the [request] parsed in [newAuthorizeRequest]. With the help of a [session] either
     * freshly constructed or restored from internal or external sources, generate a [AuthorizeResponse] which
     * encapsulates all necessary data in order to return an http response via [encodeAuthorizeResponse].
     *
     * The exceptions thrown by this method shall be regarded as OAuth error, and therefore processed by
     * [encodeAuthorizeError].
     *
     * @param request an [AuthorizeRequest] generated from [newAuthorizeRequest].
     * @param session session information either freshly generated or restored from internal or external sources.
     *
     * @return an [AuthorizeResponse] which captures all necessary return data.
     */
    fun newAuthorizeResponse(request: AuthorizeRequest, session: OAuthSession): AuthorizeResponse

    /**
     * Writes the [AuthorizeResponse] generated from [newAuthorizeResponse] as http response.
     *
     * Any exceptions thrown by this method shall be regarded as programming error.
     *
     * @param writer an abstraction of the http response.
     * @param request oauth authorize request generated from [newAuthorizeRequest], provided as reference.
     * @param response oauth authorize response generated from [newAuthorizeResponse], provide as data source.
     */
    fun encodeAuthorizeResponse(writer: HttpResponseWriter, request: AuthorizeRequest, response: AuthorizeResponse)

    /**
     * Renders any [Throwable] captured during processing into an OAuth http error response.
     *
     * Any exceptions thrown by this method shall be regarded as programming error.
     *
     * @param writer an abstraction of the http response.
     * @param request oauth authorize request generated from [newAuthorizeRequest], provided as reference.
     * @param error error captured, provided as data source.
     */
    fun encodeAuthorizeError(writer: HttpResponseWriter, request: AuthorizeRequest, error: Throwable)
}