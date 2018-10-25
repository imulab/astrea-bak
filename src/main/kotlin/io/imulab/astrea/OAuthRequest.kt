package io.imulab.astrea

import io.imulab.astrea.client.OAuthClient
import java.time.LocalDateTime
import java.util.*
import kotlin.collections.HashMap

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

class Request(private var id: String = UUID.randomUUID().toString(),
              private var reqTime: LocalDateTime = LocalDateTime.now(),
              private var client: OAuthClient,
              private val scopes: MutableSet<String> = hashSetOf(),
              private val grantedScopes: MutableSet<String> = hashSetOf(),
              private val form: MutableMap<String, List<String>> = mutableMapOf(),
              private var session: OAuthSession? = null): OAuthRequest {

    override fun setId(id: String) {
        this.id = id
    }

    override fun getId(): String = this.id

    override fun getRequestTime(): LocalDateTime = this.reqTime

    override fun getClient(): OAuthClient = this.client

    override fun getRequestScopes(): List<String> = this.scopes.toList()

    override fun setRequestScopes(scopes: List<String>) {
        this.scopes.clear()
        this.scopes.addAll(scopes)
    }

    override fun addRequestScope(scope: String) {
        if (scope.isNotBlank())
            this.scopes.add(scope)
    }

    override fun getGrantedScopes(): List<String> = this.grantedScopes.toList()

    override fun grantScope(scope: String) {
        if (scope.isNotBlank())
            this.grantedScopes.add(scope)
    }

    override fun getSession(): OAuthSession? = this.session

    override fun setSession(session: OAuthSession) {
        this.session = session
    }

    override fun getRequestForm(): UrlValues = this.form

    override fun merge(another: OAuthRequest) {
        this.reqTime = another.getRequestTime()
        this.client = another.getClient()
        this.session = another.getSession()
        another.getRequestScopes().forEach(this::addRequestScope)
        another.getGrantedScopes().forEach(this::grantScope)
        another.getRequestForm().forEach(this.form::set)
    }

    override fun sanitize(validParameters: List<String>): OAuthRequest {
        return Request(
                id = this.id,
                reqTime = this.reqTime,
                client = this.client,
                scopes = this.scopes,
                grantedScopes = this.grantedScopes,
                form = this.form.filterKeys { validParameters.contains(it) }.toMutableMap(),
                session = this.session
        )
    }
}