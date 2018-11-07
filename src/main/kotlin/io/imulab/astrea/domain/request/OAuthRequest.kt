package io.imulab.astrea.domain.request

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.spi.http.UrlValues
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
    fun getSession(): Session?

    /**
     * Sets the [Session] for current request.
     */
    fun setSession(session: Session)

    /**
     * Returns the raw http request form.
     */
    fun getRequestForm(): UrlValues

    /**
     * Merge parameters from [another] [OAuthRequest] into this one.
     */
    fun merge(another: OAuthRequest)

    /**
     * Returns a clone stripped of invalid parameters, so it can used for safe storage.
     */
    fun sanitize(validParameters: List<String>): OAuthRequest
}

