package io.imulab.astrea.domain.request

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.spi.UrlValues
import java.time.LocalDateTime
import java.util.*

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

class Request(private var id: String = UUID.randomUUID().toString(),
              private var reqTime: LocalDateTime = LocalDateTime.now(),
              private var client: OAuthClient,
              private val scopes: MutableSet<String> = hashSetOf(),
              private val grantedScopes: MutableSet<String> = hashSetOf(),
              private val form: MutableMap<String, List<String>> = mutableMapOf(),
              private var session: Session? = null) : OAuthRequest {

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

    override fun getSession(): Session? = this.session

    override fun setSession(session: Session) {
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

    open class Builder(var id: String? = null,
                       var reqTime: LocalDateTime? = null,
                       var client: OAuthClient? = null,
                       val scopes: MutableSet<String> = hashSetOf(),
                       val grantedScopes: MutableSet<String> = hashSetOf(),
                       val form: MutableMap<String, List<String>> = mutableMapOf(),
                       var session: Session? = null) {

        fun setId(id: String? = null) =
                if (id == null)
                    apply { this.id = UUID.randomUUID().toString() }
                else
                    apply { this.id = id }

        fun setRequestTime(reqTime: LocalDateTime? = null) =
                if (reqTime == null)
                    apply { this.reqTime = LocalDateTime.now() }
                else
                    apply { this.reqTime = reqTime }

        fun setClient(client: OAuthClient) = apply { this.client = client }

        fun addScopes(vararg scopes: String) = apply { this.scopes.addAll(scopes) }

        fun addGrantedScopes(vararg scopes: String) = apply { this.grantedScopes.addAll(scopes) }

        fun clearForm() = apply { form.clear() }

        fun setForm(form: UrlValues) = apply { form.forEach(this.form::set) }

        fun setForm(key: String, value: String) = apply { this.form[key] = listOf(value) }

        fun appendForm(key: String, value: String) = apply {
            if (this.form.containsKey(key))
                this.form[key] = mutableListOf<String>().apply {
                    this@apply.addAll(this@Builder.form[key]!!)
                    this@apply.add(value)
                }
            else
                setForm(key, value)
        }

        fun setSession(session: Session) = apply { this.session = session }

        open fun build(): OAuthRequest {
            if (this.id == null)
                setId()
            if (this.reqTime == null)
                setRequestTime()
            if (this.client == null)
                throw IllegalStateException("client must be set.")

            return Request(
                    id = this.id!!,
                    reqTime = this.reqTime!!,
                    client = this.client!!,
                    scopes = this.scopes,
                    grantedScopes = this.grantedScopes,
                    form = this.form,
                    session = this.session
            )
        }
    }
}