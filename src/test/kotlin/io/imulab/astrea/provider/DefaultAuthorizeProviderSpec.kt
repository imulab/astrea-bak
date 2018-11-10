package io.imulab.astrea.provider

import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.request.AuthorizeRequest
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