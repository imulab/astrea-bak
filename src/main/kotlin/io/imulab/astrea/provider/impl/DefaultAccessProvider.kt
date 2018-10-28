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
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.provider.AccessProvider
import io.imulab.astrea.spi.HttpRequestReader
import io.imulab.astrea.spi.HttpResponseWriter
import io.imulab.astrea.spi.singleValue

class DefaultAccessProvider(private val clientAuthenticator: ClientAuthenticator,
                            private val tokenEndpointHandler: TokenEndpointHandler) : AccessProvider {

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
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encodeAccessError(writer: HttpResponseWriter, request: AccessRequest, error: Throwable) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}