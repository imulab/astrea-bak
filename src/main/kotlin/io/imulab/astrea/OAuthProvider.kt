package io.imulab.astrea

import io.imulab.astrea.access.AccessRequest
import io.imulab.astrea.access.AccessResponse
import io.imulab.astrea.authorize.AuthorizeRequest
import io.imulab.astrea.authorize.AuthorizeResponse
import io.imulab.astrea.introspection.IntrospectRequest
import io.imulab.astrea.introspection.IntrospectResponse

/**
 * Interface to provide heavy lifting to most of the OAuth2 functions.
 */
interface OAuthProvider: AuthorizeProvider, AccessProvider, RevocationProvider, IntrospectionProvider

/**
 * Interface to provide the functions related to the authorize endpoint.
 */
interface AuthorizeProvider {
    /**
     * Parse incoming http request into the context for the authorize endpoint.
     */
    fun newAuthorizeRequest(reader: HttpRequestReader): AuthorizeRequest

    /**
     * Returns an authorize response which can be used to encode http response.
     */
    fun newAuthorizeResponse(request: AuthorizeRequest, session: OAuthSession): AuthorizeResponse

    /**
     * Encode authorize endpoint response to the http through [HttpResponseWriter].
     */
    fun encodeAuthorizeResponse(writer: HttpResponseWriter, request: AuthorizeRequest, response: AuthorizeResponse)

    /**
     * Encode error as the authorize endpoint response.
     */
    fun encodeAuthorizeError(writer: HttpResponseWriter, request: AuthorizeRequest, error: Throwable)
}

/**
 * Interface to provide functions related to the access endpoint.
 */
interface AccessProvider {
    /**
     * Parse incoming http request and previous session information into the context for the access endpoint.
     */
    fun newAccessRequest(reader: HttpRequestReader, session: OAuthSession): AccessRequest

    /**
     * Returns an access response which can be used to encode http response.
     */
    fun newAccessResponse(request: AccessRequest): AccessResponse

    /**
     * Encode access endpoint response to the http through [HttpResponseWriter].
     */
    fun encodeAccessResponse(writer: HttpResponseWriter, request: AccessRequest, response: AccessResponse)

    /**
     * Encode error as the access endpoint response.
     */
    fun encodeAccessError(writer: HttpResponseWriter, request: AccessRequest, error: Throwable)
}

/**
 * Interface to provide functions related to token revocation.
 */
interface RevocationProvider {
    /**
     * Handle the incoming revocation http request and perform a revocation if necessary.
     */
    fun revoke(reader: HttpRequestReader)
    /**
     * Encode http revocation response, either as a success, or with the supplied [error].
     */
    fun encodeRevocationResponse(writer: HttpResponseWriter, error: Throwable?)
}

/**
 * Interface to provide functions related to token introspection.
 */
interface IntrospectionProvider {
    /**
     * Initiate and create an introspection request.
     */
    fun newIntrospectRequest(reader: HttpRequestReader): IntrospectRequest
    /**
     * Conducts introspection and returns result of the introspection.
     */
    fun newIntrospectResponse(request: IntrospectRequest): IntrospectResponse
    /**
     * Encode successful introspection response to http.
     */
    fun encodeIntrospectReponse(writer: HttpResponseWriter, response: IntrospectResponse)
    /**
     * Encode error introspection response to http.
     */
    fun encodeIntrospectError(writer: HttpResponseWriter, error: Throwable)
}
