package io.imulab.astrea.oauth

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import java.time.LocalDateTime

class OAuthSessionTest {

    @Test
    fun `clone a default session should yield an identical one`() {
        val session = DefaultOAuthSession(username = "test_user").also {
            it.setExpiry(TokenType.AccessToken, LocalDateTime.now().plusDays(1))
        }
        val cloned = session.clone()

        assertNotEquals(session, cloned)

        assertEquals(session.getUsername(), cloned.getUsername())
        assertEquals(session.getSubject(), cloned.getSubject())
        assertEquals(session.getExpiry(TokenType.AccessToken), cloned.getExpiry(TokenType.AccessToken))
    }
}