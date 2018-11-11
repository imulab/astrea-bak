package io.imulab.astrea.provider.impl

import io.imulab.astrea.client.auth.ClientAuthenticator
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.requireNotNullOrEmpty
import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.request.impl.DefaultIntrospectRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.error.*
import io.imulab.astrea.handler.IntrospectEndpointHandler
import io.imulab.astrea.provider.IntrospectionProvider
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.http.mustSingleValue
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.spi.json.JsonEncoder
import java.time.ZoneOffset

class DefaultIntrospectionProvider(
        private val clientAuthenticator: ClientAuthenticator,
        private val introspectHandler: IntrospectEndpointHandler,
        private val jsonEncoder: JsonEncoder
) : IntrospectionProvider {

    override fun newIntrospectRequest(reader: HttpRequestReader, session: Session): IntrospectRequest {
        require(reader.method().toUpperCase() == "POST")

        if (reader.getForm().isEmpty())
            throw RequestFormIsEmptyException()

        return DefaultIntrospectRequest.Builder().also { b ->
            reader.getForm().run {
                b.token = mustSingleValue(PARAM_TOKEN).requireNotNullOrEmpty(PARAM_TOKEN)
                b.tokenType = singleValue(PARAM_TOKEN_TYPE_HINT).let { h ->
                    return@let if (h.isEmpty())
                        TokenType.Unknown
                    else
                        TokenTypeHint.fromSpecValue(h).hinted
                }
                b.session = session
                b.client = clientAuthenticator.authenticate(reader)
            }
        }.build()
    }

    override fun newIntrospectResponse(request: IntrospectRequest): IntrospectResponse {
        return introspectHandler.introspectToken(request)
    }

    override fun encodeIntrospectResponse(writer: HttpResponseWriter, response: IntrospectResponse) {
        writer.setStatus(200)
        writer.setHeader("Content-Type", "application/json;charset=UTF-8")

        if (!response.isActive()) {
            writer.writeBody(jsonEncoder.encode(mapOf("active" to false)))
            return
        }

        checkNotNull(response.getAccessRequest())

        response.getAccessRequest()!!.let { ar ->
            mutableMapOf<String, Any>().also { m ->
                m[PARAM_ACTIVE] = true
                m[PARAM_CLIENT_ID] = ar.getClient().getId()
                ar.getGrantedScopes().joinToString(SPACE).let {
                    if (it.isNotBlank())
                        m[PARAM_SCOPE] = it
                }
                ar.getSession()?.getExpiry(TokenType.AccessToken)?.toEpochSecond(ZoneOffset.UTC)?.let {
                    m["exp"] = it
                }
                m["iat"] = ar.getRequestTime().toEpochSecond(ZoneOffset.UTC)
                ar.getSession()?.getSubject()?.let {
                    if (it.isNotBlank())
                        m["sub"] = it
                }
                ar.getSession()?.getUsername()?.let {
                    if (it.isNotBlank())
                        m[PARAM_USERNAME] = it
                }
            }
        }.let {
            writer.writeBody(jsonEncoder.encode(it))
        }
    }

    override fun encodeIntrospectError(writer: HttpResponseWriter, error: Throwable) {
        writer.setHeader("Content-Type", "application/json;charset=UTF-8")
        when (error) {
            is InvalidRequestException,
            is InvalidGrantException,
            is InvalidClientException -> {
                (error as OAuthException).run {
                    writer.setStatus(this.statusCode())
                    writer.writeBody(jsonEncoder.encode(this.toMap()))
                }
            }
            else -> {
                writer.setStatus(200)
                writer.writeBody(jsonEncoder.encode(mapOf("active" to false)))
            }
        }
    }
}