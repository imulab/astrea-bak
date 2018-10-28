package io.imulab.astrea.domain

import io.imulab.astrea.error.MalformedRedirectUriException
import io.imulab.astrea.error.RedirectUriHasFragmentException
import io.imulab.astrea.error.UnmatchedRedirectUriException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable

class RedirectUriTest {

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
        assertEquals(registered, registered.determineRedirectUri(listOf(registered, another)))
    }

    @Test
    fun `non-registered redirect uri should be rejected`() {
        val notRegistered = "https://hello.imulab.io/callback"
        val another = "https://world.imulab.io/callback"
        val shouldThrow = Executable { notRegistered.determineRedirectUri(listOf(another)) }
        assertThrows(UnmatchedRedirectUriException::class.java, shouldThrow)
    }

    @Test
    fun `empty supply should match the only registered redirect uri`() {
        val registered = "https://hello.imulab.io/callback"
        assertEquals(registered, null.determineRedirectUri(listOf(registered)))
    }

    @Test
    fun `empty supply should fail when multiple redirect uri registered`() {
        val one = "https://hello.imulab.io/callback"
        val another = "https://world.imulab.io/callback"
        val shouldThrow = Executable { "".determineRedirectUri(listOf(one, another)) }
        assertThrows(UnmatchedRedirectUriException::class.java, shouldThrow)
    }

}