package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientNoneAuthenticator
import io.imulab.astrea.domain.AuthMethod
import io.imulab.astrea.spi.http.HttpRequestReader
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mindrot.jbcrypt.BCrypt
import org.mockito.Mockito

class ClientNoneAuthenticatorTest {

    @Test
    fun `a public oauth client should pass`() {
        val authenticator = ClientNoneAuthenticator(clientManager)
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    "client_id" to listOf("foo")
            ))
        }
        Assertions.assertTrue(authenticator.supports(request))
        Assertions.assertEquals("foo", authenticator.authenticate(request).getId())
    }

    @Test
    fun `a public oidc client with none auth method should pass`() {
        val authenticator = ClientNoneAuthenticator(clientManager)
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    "client_id" to listOf("bar")
            ))
        }
        Assertions.assertTrue(authenticator.supports(request))
        Assertions.assertEquals("bar", authenticator.authenticate(request).getId())
    }

    @Test
    fun `a non-public client should not pass`() {
        val authenticator = ClientNoneAuthenticator(clientManager)
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    "client_id" to listOf("private")
            ))
        }
        Assertions.assertFalse(authenticator.supports(request))
    }

    private val clientManager: ClientManager by lazy {
        val mocked = Mockito.mock(ClientManager::class.java)

        Mockito.`when`(mocked.getClient("foo")).thenReturn(DefaultOAuthClient(
                id = "foo",
                secret = BCrypt.hashpw("s3cret", BCrypt.gensalt()).toByteArray(),
                public = true
        ))

        Mockito.`when`(mocked.getClient("bar")).thenReturn(DefaultOidcClient(
                oauth = DefaultOAuthClient(
                        id = "bar",
                        secret = BCrypt.hashpw("s3cret", BCrypt.gensalt()).toByteArray(),
                        public = true
                ),
                tokenEndpointAuth = AuthMethod.None
        ))

        Mockito.`when`(mocked.getClient("private")).thenReturn(DefaultOidcClient(
                oauth = DefaultOAuthClient(
                        id = "private",
                        secret = BCrypt.hashpw("s3cret", BCrypt.gensalt()).toByteArray()
                ),
                tokenEndpointAuth = AuthMethod.None
        ))

        return@lazy mocked
    }
}