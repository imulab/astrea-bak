package io.imulab.astrea.support

import com.beust.klaxon.Klaxon
import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.auth.ClientAuthenticator
import io.imulab.astrea.client.auth.ClientBearerPreIntrospectionAuthenticator
import io.imulab.astrea.client.auth.ClientSecretBasicAuthenticator
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.StringEqualityScopeStrategy
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.IntrospectEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.handler.introspect.AccessTokenJwtIntrospectHandler
import io.imulab.astrea.handler.introspect.RefreshTokenStorageIntrospectHandler
import io.imulab.astrea.provider.impl.DefaultAccessProvider
import io.imulab.astrea.provider.impl.DefaultAuthorizeProvider
import io.imulab.astrea.provider.impl.DefaultIntrospectionProvider
import io.imulab.astrea.spi.http.HttpClient
import io.imulab.astrea.spi.json.JsonEncoder
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.mockito.Mockito.mock
import java.nio.charset.StandardCharsets

object ProviderSupport {

    object Authorize {

        fun forTestProvider(): DefaultAuthorizeProvider {
            return DefaultAuthorizeProvider(
                    authorizeHandler = mock(AuthorizeEndpointHandler::class.java),
                    scopeStrategy = StringEqualityScopeStrategy,
                    expectedAudience = "test",
                    httpClient = mock(HttpClient::class.java),
                    clientStore = ClientSupport.clientManager(ClientSupport.foo(), ClientSupport.bar()),
                    jsonEncoder = mock(JsonEncoder::class.java)
            )
        }

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

    object Access {

        fun forTestJsonCapability(): DefaultAccessProvider {
            return DefaultAccessProvider(
                    clientAuthenticator = mock(ClientAuthenticator::class.java),
                    jsonEncoder = object : JsonEncoder {
                        override fun encode(any: Any, pretty: Boolean): ByteArray {
                            return Klaxon().toJsonString(any).toByteArray(StandardCharsets.UTF_8)
                        }
                    },
                    outputDebugInErrorResponse = true,
                    tokenEndpointHandler = mock(TokenEndpointHandler::class.java)
            )
        }
    }

    object Introspect {

        fun forDefaultTest(memoryStorage: MemoryStorage): DefaultIntrospectionProvider {
            return DefaultIntrospectionProvider(
                    clientAuthenticator = ClientAuthenticator.customChain(
                            ClientSecretBasicAuthenticator(
                                    clientManager = ClientSupport.clientManager(
                                            ClientSupport.foo(),
                                            ClientSupport.bar()),
                                    passwordEncoder = BCryptPasswordEncoder()),
                            ClientBearerPreIntrospectionAuthenticator(
                                    accessTokenStorage = memoryStorage,
                                    accessTokenStrategy = TokenSupport.AccessToken.defaultStrategy)
                    ),
                    jsonEncoder = mock(JsonEncoder::class.java),
                    introspectHandler = IntrospectEndpointHandler.with(
                            AccessTokenJwtIntrospectHandler(
                                    jwtRs256 = JwtRs256(KeySupport.defaultJwk),
                                    issuer = TokenSupport.ISSUER),
                            RefreshTokenStorageIntrospectHandler(
                                    refreshTokenStorage = memoryStorage,
                                    refreshTokenStrategy = TokenSupport.RefreshToken.defaultStrategy)
                    )
            )
        }
    }
}