package io.imulab.astrea.provider.impl

import io.imulab.astrea.client.auth.ClientAuthenticator
import io.imulab.astrea.domain.PARAM_TOKEN
import io.imulab.astrea.domain.PARAM_TOKEN_TYPE_HINT
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.TokenTypeHint
import io.imulab.astrea.domain.extension.requireNotNullOrEmpty
import io.imulab.astrea.domain.request.impl.DefaultRevocationRequest
import io.imulab.astrea.error.OAuthException
import io.imulab.astrea.error.RequestFormIsEmptyException
import io.imulab.astrea.handler.RevocationEndpointHandler
import io.imulab.astrea.provider.RevocationProvider
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.http.mustSingleValue
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.spi.json.JsonEncoder

class DefaultRevocationProvider(
        private val clientAuthenticator: ClientAuthenticator,
        private val handler: RevocationEndpointHandler,
        private val jsonEncoder: JsonEncoder
): RevocationProvider {

    override fun revoke(reader: HttpRequestReader) {
        require(reader.method().toUpperCase() == "POST")

        if (reader.getForm().isEmpty())
            throw RequestFormIsEmptyException()

        val request = DefaultRevocationRequest.Builder().also { b ->
            reader.getForm().run {
                b.token = mustSingleValue(PARAM_TOKEN).requireNotNullOrEmpty(PARAM_TOKEN)
                b.tokenType = singleValue(PARAM_TOKEN_TYPE_HINT).let { h ->
                    return@let if (h.isEmpty())
                        TokenType.Unknown
                    else
                        TokenTypeHint.fromSpecValue(h).hinted
                }
                b.client = clientAuthenticator.authenticate(reader)
            }
        }.build()

        if (!handler.revokeToken(request))
            throw RevocationDidNotSucceedException
    }

    override fun encodeRevocationResponse(writer: HttpResponseWriter, error: Throwable?) {
        writer.setHeader("Content-Type", "application/json;charset=UTF-8")

        when (error) {
            null -> {
                writer.setStatus(200)
                writer.writeBody(jsonEncoder.encode(mapOf("success" to true)))
            }
            is RevocationDidNotSucceedException -> {
                writer.setStatus(200)
                writer.writeBody(jsonEncoder.encode(mapOf("success" to false)))
            }
            else -> {
                val e = error as? OAuthException ?: OAuthException.ServerException(error)
                writer.setStatus(e.statusCode())
                writer.writeBody(jsonEncoder.encode(e.toMap()))
            }
        }
    }

    // internal exception used as communication signal, not expected to be used elsewhere.
    private object RevocationDidNotSucceedException: RuntimeException()
}