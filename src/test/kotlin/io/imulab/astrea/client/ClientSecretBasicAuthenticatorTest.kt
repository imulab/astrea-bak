package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientSecretBasicAuthenticator
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.error.ClientAuthenticationException
import io.imulab.astrea.spi.http.HttpRequestReader
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mindrot.jbcrypt.BCrypt
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.util.*

class ClientSecretBasicAuthenticatorTest {

    @Test
    fun `missing basic authorization header is not supported`() {
        val authenticator = ClientSecretBasicAuthenticator(
                clientManager = clientManager,
                passwordEncoder = BCryptPasswordEncoder()
        )

        assertFalse(authenticator.supports(mock(HttpRequestReader::class.java).also {
            `when`(it.getHeader("Authorization")).thenReturn("")
        }))
    }

    @Test
    fun `correct credentials should authenticate successfully`() {
        val authenticator = ClientSecretBasicAuthenticator(
                clientManager = clientManager,
                passwordEncoder = BCryptPasswordEncoder()
        )

        val request = mock(HttpRequestReader::class.java).also {
            `when`(it.getHeader("Authorization")).thenReturn(
                    "Basic " + Base64.getEncoder().encodeToString("foo:s3cret".toByteArray())
            )
        }

        assertTrue(authenticator.supports(request))
        val client = authenticator.authenticate(request)
        assertEquals("foo", client.getId())
    }

    @Test
    fun `incorrect credential should fail authentication`() {
        val authenticator = ClientSecretBasicAuthenticator(
                clientManager = clientManager,
                passwordEncoder = BCryptPasswordEncoder()
        )

        val request = mock(HttpRequestReader::class.java).also {
            `when`(it.getHeader("Authorization")).thenReturn(
                    "Basic " + Base64.getEncoder().encodeToString("foo:incorrect".toByteArray())
            )
        }

        assertTrue(authenticator.supports(request))
        assertThrows(ClientAuthenticationException::class.java) {
            authenticator.authenticate(request)
        }
    }

    @Test
    fun `bad http basic format should fail authentication`() {
        val authenticator = ClientSecretBasicAuthenticator(
                clientManager = clientManager,
                passwordEncoder = BCryptPasswordEncoder()
        )

        val request = mock(HttpRequestReader::class.java).also {
            `when`(it.getHeader("Authorization")).thenReturn("Basic invalidstring")
        }

        assertTrue(authenticator.supports(request))
        assertThrows(ClientAuthenticationException::class.java) {
            authenticator.authenticate(request)
        }
    }

    private val clientManager: ClientManager by lazy {
        val mocked = mock(ClientManager::class.java)

        `when`(mocked.getClient("foo")).thenReturn(DefaultOAuthClient(
                id = "foo",
                secret = BCrypt.hashpw("s3cret", BCrypt.gensalt()).toByteArray()
        ))

        return@lazy mocked
    }
}