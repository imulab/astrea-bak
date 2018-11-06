package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientSecretPostAuthenticator
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.spi.http.HttpRequestReader
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mindrot.jbcrypt.BCrypt
import org.mockito.Mockito

class ClientSecretPostAuthenticatorTest {

    @Test
    fun `non http post is not supported`() {
        val authenticator = ClientSecretPostAuthenticator(
                clientManager = clientManager,
                passwordEncoder = BCryptPasswordEncoder()
        )

        Assertions.assertFalse(authenticator.supports(Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.method()).thenReturn("GET")
        }))
    }

    @Test
    fun `correct credentials should authenticate successfully`() {
        val authenticator = ClientSecretPostAuthenticator(
                clientManager = clientManager,
                passwordEncoder = BCryptPasswordEncoder()
        )

        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.method()).thenReturn("POST")
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    "client_id" to listOf("foo"),
                    "client_secret" to listOf("s3cret")
            ))
        }

        Assertions.assertTrue(authenticator.supports(request))
        val client = authenticator.authenticate(request)
        Assertions.assertEquals("foo", client.getId())
    }

    @Test
    fun `incorrect credentials should fail authentication`() {
        val authenticator = ClientSecretPostAuthenticator(
                clientManager = clientManager,
                passwordEncoder = BCryptPasswordEncoder()
        )

        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.method()).thenReturn("POST")
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    "client_id" to listOf("foo"),
                    "client_secret" to listOf("invalid")
            ))
        }

        Assertions.assertTrue(authenticator.supports(request))
        Assertions.assertThrows(InvalidClientException.AuthenticationFailed::class.java) {
            authenticator.authenticate(request)
        }
    }

    private val clientManager: ClientManager by lazy {
        val mocked = Mockito.mock(ClientManager::class.java)

        Mockito.`when`(mocked.getClient("foo")).thenReturn(DefaultOAuthClient(
                id = "foo",
                secret = BCrypt.hashpw("s3cret", BCrypt.gensalt()).toByteArray()
        ))

        return@lazy mocked
    }
}