package io.imulab.astrea.domain

import io.imulab.astrea.error.RequestParameterInvalidValueException
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object RedirectUriSpec : Spek({

    describe("validity") {

        it("""
            relative uri is not a valid redirect uri
        """.trimIndent()) {
            assertThatExceptionOfType(RequestParameterInvalidValueException.MalformedRedirectUri::class.java)
                    .isThrownBy { "foo/bar?hey".checkValidRedirectUri() }
        }

        it("""
            uri containing fragment is not a valid redirect uri
        """.trimIndent()) {
            assertThatExceptionOfType(RequestParameterInvalidValueException.MalformedRedirectUri::class.java)
                    .isThrownBy { "https://foo.com/bar?hey#hello".checkValidRedirectUri() }
        }
    }

    describe("determine redirect uri") {

        it("""
            registered redirect uri should be determined
        """.trimIndent()) {
            val registered = "https://hello.imulab.io/callback"
            val another = "https://world.imulab.io/callback"
            assertThat(registered.determineRedirectUri(listOf(registered, another)))
                    .isEqualTo(registered)
        }

        it("""
            non-registered redirect uri should be rejected
        """.trimIndent()) {
            val notRegistered = "https://hello.imulab.io/callback"
            val another = "https://world.imulab.io/callback"
            assertThatExceptionOfType(RequestParameterInvalidValueException.RougeRedirectUri::class.java)
                    .isThrownBy { notRegistered.determineRedirectUri(listOf(another)) }
        }

        it("""
            empty supply should match the only registered redirect uri
        """.trimIndent()) {
            val registered = "https://hello.imulab.io/callback"
            assertThat(null.determineRedirectUri(listOf(registered))).isEqualTo(registered)
        }

        it("""
            empty supply should fail when multiple redirect uri registered
        """.trimIndent()) {
            val one = "https://hello.imulab.io/callback"
            val another = "https://world.imulab.io/callback"
            assertThatExceptionOfType(RequestParameterInvalidValueException.MultipleRedirectUriRegistered::class.java)
                    .isThrownBy { "".determineRedirectUri(listOf(one, another)) }
        }
    }
})