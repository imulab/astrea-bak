package io.imulab.astrea.provider

import io.imulab.astrea.domain.PARAM_SCOPE
import io.imulab.astrea.domain.PARAM_STATE
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.error.OAuthException
import io.imulab.astrea.support.HttpSupport
import io.imulab.astrea.support.ProviderSupport
import io.imulab.astrea.support.RequestSupport
import org.apache.http.client.utils.URIBuilder
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.lang.RuntimeException

object DefaultAuthorizeProviderSpec : Spek({

    describe("write responses") {

        val provider: AuthorizeProvider = ProviderSupport.Authorize.forTestJsonCapability()
        val request: AuthorizeRequest = RequestSupport.newAuthorizeRequest()

        it("""
            encode response as queries
        """.trimIndent()) {
            val response: AuthorizeResponse = DefaultAuthorizeResponse().also {
                it.addQuery(PARAM_SCOPE, "foo bar")
                it.addQuery(PARAM_STATE, "1234567890")
            }
            val writer: HttpSupport.MapHttpResponseWriter = HttpSupport.response()

            assertThatCode {
                provider.encodeAuthorizeResponse(writer, request, response)
            }.doesNotThrowAnyException()

            writer.assertStatus(302)
            URIBuilder(writer.getHeader("Location")).run {
                assertThat(queryParams.find { it.name == PARAM_SCOPE }?.value)
                        .isNotNull()
                        .asString()
                        .contains("foo", "bar")
                assertThat(queryParams.find { it.name == PARAM_STATE }?.value)
                        .isNotNull()
                        .asString()
                        .isEqualTo("1234567890")
            }
        }

        it("""
            encode response as fragments
        """.trimIndent()) {
            val response: AuthorizeResponse = DefaultAuthorizeResponse().also {
                it.addFragment(PARAM_SCOPE, "foo bar")
                it.addFragment(PARAM_STATE, "1234567890")
            }
            val writer: HttpSupport.MapHttpResponseWriter = HttpSupport.response()

            assertThatCode {
                provider.encodeAuthorizeResponse(writer, request, response)
            }.doesNotThrowAnyException()

            writer.assertStatus(302)
            URIBuilder(writer.getHeader("Location")).run {
                assertThat(fragment).contains("$PARAM_SCOPE=foo bar")
                assertThat(fragment).contains("$PARAM_STATE=1234567890")
            }
        }
    }

    describe("write errors") {

        val provider: AuthorizeProvider = ProviderSupport.Authorize.forTestJsonCapability()
        val error = object : OAuthException("test-code", "test-description") {
            override fun statusCode(): Int = 400
        }

        it("""
            encode oauth exception as queries
        """.trimIndent()) {
            val request: AuthorizeRequest = RequestSupport.newAuthorizeRequest()
            val writer: HttpSupport.MapHttpResponseWriter = HttpSupport.response()

            assertThatCode {
                provider.encodeAuthorizeError(writer, request, error)
            }.doesNotThrowAnyException()

            writer.assertStatus(302)

            URIBuilder(writer.getHeader("Location")).run {
                listOf(
                        Pair("status_code", "400"),
                        Pair("error_description", "test-description"),
                        Pair("error", "test-code")
                ).forEach { pair ->
                    assertThat(this)
                            .extracting { it.queryParams.find { p -> p.name == pair.first }?.value }
                            .isNotNull()
                            .asString()
                            .isEqualTo(pair.second)
                }
            }
        }

        it("""
            encode oauth exception as fragments
        """.trimIndent()) {
            val request: AuthorizeRequest = RequestSupport.newAuthorizeRequest(
                    responseTypes = setOf(ResponseType.Token)
            )
            val writer: HttpSupport.MapHttpResponseWriter = HttpSupport.response()

            assertThatCode {
                provider.encodeAuthorizeError(writer, request, error)
            }.doesNotThrowAnyException()

            writer.assertStatus(302)

            URIBuilder(writer.getHeader("Location")).run {
                listOf(
                        Pair("status_code", "400"),
                        Pair("error_description", "test-description"),
                        Pair("error", "test-code")
                ).forEach { pair ->
                    assertThat(this.fragment)
                            .contains("${pair.first}=${pair.second}")
                }
            }
        }

        it("""
            encode generic error
        """.trimIndent()) {
            val request: AuthorizeRequest = RequestSupport.newAuthorizeRequest()
            val writer: HttpSupport.MapHttpResponseWriter = HttpSupport.response()

            assertThatCode {
                provider.encodeAuthorizeError(writer, request, RuntimeException("generic"))
            }.doesNotThrowAnyException()

            writer.assertStatus(302)

            URIBuilder(writer.getHeader("Location")).run {
                listOf(
                        Pair("status_code", "500"),
                        Pair("error_description", "generic"),
                        Pair("error", "server_error")
                ).forEach { pair ->
                    assertThat(this)
                            .extracting { it.queryParams.find { p -> p.name == pair.first }?.value }
                            .isNotNull()
                            .asString()
                            .isEqualTo(pair.second)
                }
            }
        }
    }
})