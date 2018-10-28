package io.imulab.astrea.domain

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.domain.request.Request
import io.imulab.astrea.domain.session.impl.DefaultSession
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class OAuthRequestTest {

    @Test
    fun `merge should combine requests with the argument having higher precedence`() {
        val original = Request(
                client = DefaultOAuthClient("foo", ByteArray(0), emptyList()),
                scopes = mutableSetOf("one", "two"),
                grantedScopes = mutableSetOf("one"),
                form = mutableMapOf("x" to listOf("1", "2")),
                session = DefaultSession()
        )
        val merger = Request(
                client = DefaultOAuthClient("bar", ByteArray(0), emptyList()),
                scopes = mutableSetOf("three"),
                grantedScopes = mutableSetOf("three"),
                form = mutableMapOf("y" to listOf("3", "4")),
                session = DefaultSession()
        )

        original.merge(merger)

        assertEquals(merger.getClient(), original.getClient())
        assertIterableEquals(setOf("one", "two", "three"), original.getRequestScopes())
        assertIterableEquals(setOf("one", "three"), original.getGrantedScopes())
        assertIterableEquals(listOf("1", "2"), original.getRequestForm()["x"])
        assertIterableEquals(listOf("3", "4"), original.getRequestForm()["y"])
        assertEquals(merger.getSession(), original.getSession())
    }

    @Test
    fun `sanitize should remove any unlisted keys from forms`() {
        val req = Request(
                client = DefaultOAuthClient("foo", ByteArray(0), emptyList()),
                form = mutableMapOf(
                        "x" to listOf("1"),
                        "y" to listOf("2"),
                        "z" to listOf("3")
                )
        )
        val sanitized = req.sanitize(listOf("x", "z"))

        assertNull(sanitized.getRequestForm()["y"])
        assertIterableEquals(listOf("1"), sanitized.getRequestForm()["x"])
        assertIterableEquals(listOf("3"), sanitized.getRequestForm()["z"])
    }
}