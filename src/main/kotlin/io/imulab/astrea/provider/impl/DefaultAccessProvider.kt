package io.imulab.astrea.provider.impl

import io.imulab.astrea.client.auth.ClientAuthenticator
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.DefaultAccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.error.EmptyRequestException
import io.imulab.astrea.error.HttpMethodMismatchException
import io.imulab.astrea.error.toRfc6749Error
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.provider.AccessProvider
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.spi.json.JsonEncoder

class DefaultAccessProvider(private val clientAuthenticator: ClientAuthenticator,
                            private val tokenEndpointHandler: TokenEndpointHandler,
                            private val jsonEncoder: JsonEncoder,
                            private val outputDebugInErrorResponse: Boolean = false) : AccessProvider {

    override fun newAccessRequest(reader: HttpRequestReader, session: Session): AccessRequest {
        when {
            reader.method() != "POST" -> throw HttpMethodMismatchException("POST", reader.method())
            reader.getForm().isEmpty() -> throw EmptyRequestException()
        }

        val accessRequest = DefaultAccessRequest.Builder().also {
            it.setSession(session)
            it.setForm(reader.getForm())
            it.addScopes(*(reader
                    .getForm()
                    .singleValue("scope")
                    .split(" ")
                    .filter { it.isNotEmpty() }
                    .toTypedArray()
                    ))
            it.addGrantType(*(reader
                    .getForm()
                    .singleValue("grant_type")
                    .split(" ")
                    .filter { it.isNotEmpty() }
                    .map { GrantType.fromSpecValue(it) }
                    .toTypedArray()
                    ))
            it.client = clientAuthenticator.authenticate(reader)
        }.build() as AccessRequest

        tokenEndpointHandler.handleAccessRequest(accessRequest)

        return accessRequest
    }

    override fun newAccessResponse(request: AccessRequest): AccessResponse {
        val response = DefaultAccessResponse()

        tokenEndpointHandler.populateAccessResponse(request, response)
        if (response.getAccessToken().isEmpty() || response.getTokenType() == TokenType.Unknown)
            throw RuntimeException("Token not generated. An internal error has occured.")

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

    override fun encodeAccessError(writer: HttpResponseWriter, request: AccessRequest, error: Throwable) {
        val rfc6749Error = error.toRfc6749Error()
        writer.setHeader("Content-Type", "application/json;charset=UTF-8")
        writer.setStatus(rfc6749Error.getStatusCode())
        writer.writeBody(jsonEncoder.encode(rfc6749Error.toMap(outputDebugInErrorResponse)))
    }
}