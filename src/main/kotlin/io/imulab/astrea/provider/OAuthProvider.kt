package io.imulab.astrea.provider

import io.imulab.astrea.HttpRequestReader
import io.imulab.astrea.HttpResponseWriter
import io.imulab.astrea.access.AccessRequest
import io.imulab.astrea.access.AccessResponse
import io.imulab.astrea.authorize.AuthorizeRequest
import io.imulab.astrea.authorize.AuthorizeResponse
import io.imulab.astrea.introspection.IntrospectRequest
import io.imulab.astrea.introspection.IntrospectResponse
import io.imulab.astrea.oauth.OAuthSession

/**
 * The main entry point of the SDK. This interface provides heavy lifting to most of the OAuth2 functions.
 *
 * The interface itself is a placeholder, it does not declare any methods. Instead, it is composed of a series of
 * sub-interfaces in order to clearly separate boundaries between functions. This is intended to promote readability
 * and maintainability of source codes.
 *
 * @see AuthorizeProvider
 * @see AccessProvider
 * @see RevocationProvider
 * @see IntrospectionProvider
 */
interface OAuthProvider :
        AuthorizeProvider,
        AccessProvider,
        RevocationProvider,
        IntrospectionProvider





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
