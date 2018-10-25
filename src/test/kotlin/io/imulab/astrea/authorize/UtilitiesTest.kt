package io.imulab.astrea.authorize

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable

class UtilitiesTest {

    @Test
    fun `relative uri is not a valid redirect uri`() {
        val shouldThrow = Executable {
            "foo/bar?hey".checkValidRedirectUri()
        }
        assertThrows(MalformedRedirectUriException::class.java, shouldThrow)
    }

    @Test
    fun `uri containing fragment is not a valid redirect uri`() {
        val shouldThrow = Executable {
            "https://foo.com/bar?hey#hello".checkValidRedirectUri()
        }
        assertThrows(RedirectUriHasFragmentException::class.java, shouldThrow)
    }

    @Test
    fun `registered redirect uri should be determined`() {
        val registered = "https://hello.imulab.io/callback"
        val another = "https://world.imulab.io/callback"
        assertEquals(registered, determineRedirectUri(registered, listOf(registered, another)))
    }

    @Test
    fun `non-registered redirect uri should be rejected`() {
        val notRegistered = "https://hello.imulab.io/callback"
        val another = "https://world.imulab.io/callback"
        val shouldThrow = Executable { determineRedirectUri(notRegistered, listOf(another)) }
        assertThrows(UnmatchedRedirectUriException::class.java, shouldThrow)
    }

    @Test
    fun `empty supply should match the only registered redirect uri`() {
        val registered = "https://hello.imulab.io/callback"
        assertEquals(registered, determineRedirectUri(null, listOf(registered)))
    }

    @Test
    fun `empty supply should fail when multiple redirect uri registered`() {
        val one = "https://hello.imulab.io/callback"
        val another = "https://world.imulab.io/callback"
        val shouldThrow = Executable { determineRedirectUri("", listOf(one, another)) }
        assertThrows(UnmatchedRedirectUriException::class.java, shouldThrow)
    }

}