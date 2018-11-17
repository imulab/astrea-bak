package io.imulab.astrea.provider.impl

import io.imulab.astrea.client.auth.ClientAuthenticator
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.PARAM_GRANT_TYPE
import io.imulab.astrea.domain.PARAM_SCOPE
import io.imulab.astrea.domain.SPACE
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.impl.DefaultAccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.error.OAuthException
import io.imulab.astrea.error.RequestFormIsEmptyException
import io.imulab.astrea.error.RequestNotProcessedException
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.provider.AccessProvider
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.http.mustSingleValue
import io.imulab.astrea.spi.json.JsonEncoder

class DefaultAccessProvider(private val clientAuthenticator: ClientAuthenticator,
                            private val tokenEndpointHandler: TokenEndpointHandler,
                            private val jsonEncoder: JsonEncoder,
                            private val outputDebugInErrorResponse: Boolean = false) : AccessProvider {

    override fun newAccessRequest(reader: HttpRequestReader, session: Session): AccessRequest {
        require(reader.method().toUpperCase() == "POST")

        if (reader.getForm().isEmpty())
            throw RequestFormIsEmptyException()

        val accessRequest = DefaultAccessRequest.Builder().also { b ->
            b.setSession(session)

            reader.getForm().run {
                b.setForm(this)

                mustSingleValue(PARAM_SCOPE)
                        .split(SPACE)
                        .filter { it.isNotEmpty() }
                        .forEach { b.addScopes(it) }

                mustSingleValue(PARAM_GRANT_TYPE)
                        .split(SPACE)
                        .filter { it.isNotEmpty() }
                        .map { GrantType.fromSpecValue(it) }
                        .forEach { b.addGrantType(it) }
            }

            b.client = clientAuthenticator.authenticate(reader)
        }.build() as AccessRequest

        tokenEndpointHandler.handleAccessRequest(accessRequest)

        return accessRequest
    }

    override fun newAccessResponse(request: AccessRequest): AccessResponse {
        val response = DefaultAccessResponse()

        tokenEndpointHandler.populateAccessResponse(request, response)
        if (response.getAccessToken().isEmpty())
            throw RequestNotProcessedException()

        return response
    }

    override fun encodeAccessResponse(writer: HttpResponseWriter, request: AccessRequest, response: AccessResponse) {
        val json = jsonEncoder.encode(response.toMap())

        writer.let {
            it.setStatus(200)

            it.setHeader("Content-Type", "application/json;charset=UTF-8")
            it.setHeader("Cache-Control", "no-store")
            it.setHeader("Pragma", "no-cache")

            it.writeBody(json)
        }
    }

    override fun encodeAccessError(writer: HttpResponseWriter, request: AccessRequest?, error: Throwable) {
        val exception = error as? OAuthException ?: OAuthException.ServerException(error)

        writer.run {
            setStatus(exception.statusCode())
            setHeader("Content-Type", "application/json;charset=UTF-8")
            exception.extraHeaders().forEach(this::setHeader)
            writeBody(jsonEncoder.encode(exception.toMap(outputDebugInErrorResponse)))
        }
    }
}