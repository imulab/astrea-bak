package io.imulab.astrea

import io.imulab.astrea.client.OAuthClient
import java.time.LocalDateTime

/**
 * All requests in the context of OAuth2.
 */
interface OAuthRequest {

    /**
     * Set unique [id] to this request.
     */
    fun setId(id: String)

    /**
     * Returns id of this request.
     */
    fun getId(): String

    /**
     * Returns the request time.
     */
    fun getRequestTime(): LocalDateTime

    /**
     * Returns the requesting client.
     */
    fun getClient(): OAuthClient

    /**
     * Returns the requested OAuth2 scopes.
     */
    fun getRequestScopes(): List<String>

    /**
     * Set the request OAuth2 [scopes].
     */
    fun setRequestScopes(scopes: List<String>)

    /**
     * Add a new request scope.
     */
    fun addRequestScope(scope: String)

    /**
     * Returns all granted scopes.
     */
    fun getGrantedScopes(): List<String>

    /**
     * Grant a scope.
     */
    fun grantScope(scope: String)

    /**
     * Returns the current user session, if exists; nil otherwise.
     */
    fun getSession(): OAuthSession?

    /**
     * Sets the [OAuthSession] for current request.
     */
    fun setSession(session: OAuthSession)

    /**
     * Returns the raw http request form.
     */
    fun getRequestForm(): Map<String, List<String>>

    /**
     * Merge parameters from [another] [OAuthRequest] into this one.
     */
    fun merge(another: OAuthRequest)

    /**
     * Returns a clone stripped of invalid parameters, so it can used for safe storage.
     */
    fun sanitize(validParameters: List<String>): OAuthRequest
}
