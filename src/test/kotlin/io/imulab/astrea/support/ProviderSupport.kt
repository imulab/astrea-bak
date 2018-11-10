package io.imulab.astrea.support

import com.beust.klaxon.Klaxon
import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.provider.impl.DefaultAuthorizeProvider
import io.imulab.astrea.spi.http.HttpClient
import io.imulab.astrea.spi.json.JsonEncoder
import org.mockito.Mockito.mock
import java.nio.charset.StandardCharsets

object ProviderSupport {

    object Authorize {

        fun forTestJsonCapability(): DefaultAuthorizeProvider {
            return DefaultAuthorizeProvider(
                    authorizeHandler = mock(AuthorizeEndpointHandler::class.java),
                    scopeStrategy = mock(ScopeStrategy::class.java),
                    expectedAudience = "test",
                    httpClient = mock(HttpClient::class.java),
                    clientStore = mock(ClientManager::class.java),
                    outputDebugInErrorResponse = false,
                    jsonEncoder = object : JsonEncoder {
                        override fun encode(any: Any, pretty: Boolean): ByteArray {
                            return Klaxon().toJsonString(any).toByteArray(StandardCharsets.UTF_8)
                        }
                    }
            )
        }
    }
}