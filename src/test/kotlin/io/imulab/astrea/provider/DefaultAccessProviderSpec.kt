package io.imulab.astrea.provider

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.error.OAuthException
import io.imulab.astrea.support.HttpSupport
import io.imulab.astrea.support.ProviderSupport
import io.imulab.astrea.support.RequestSupport
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.time.LocalDateTime

object DefaultAccessProviderSpec : Spek({

    describe("write response") {
        val provider: AccessProvider = ProviderSupport.Access.forTestJsonCapability()
        val request: AccessRequest = RequestSupport.newAccessRequest()

        it("""
            encode response
        """.trimIndent()) {
            val response: AccessResponse = DefaultAccessResponse().also {
                it.setAccessToken("test-access-token")
                it.setExpiry(LocalDateTime.now().plusDays(1))
                it.setScopes(listOf("foo", "bar"))
                it.setTokenType(TokenType.Bearer)
                it.setExtra("refresh_token", "test-refresh-token")
            }
            val writer: HttpSupport.MapHttpResponseWriter = HttpSupport.response()

            assertThatCode {
                provider.encodeAccessResponse(writer, request, response)
            }.doesNotThrowAnyException()

            writer.assertStatus(200)
            writer.assertHeader("Content-Type", "application/json;charset=UTF-8")
            writer.assertHeader("Pragma", "no-cache")
            writer.assertHeader("Cache-Control", "no-store")
            writer.getBodyAsJsonMap().run {
                assertThat(this[PARAM_ACCESS_TOKEN]).isNotNull().asString().isEqualTo("test-access-token")
                assertThat(this[PARAM_TOKEN_TYPE]).isNotNull().asString().isEqualTo(TokenType.Bearer.specValue)
                assertThat(this[PARAM_REFRESH_TOKEN]).isNotNull().asString().isEqualTo("test-refresh-token")
                assertThat(this[PARAM_SCOPE]).isNotNull().asString().contains("foo", "bar")
                return@run
            }
        }
    }

    describe("write error") {

        val provider: AccessProvider = ProviderSupport.Access.forTestJsonCapability()
        val request: AccessRequest = RequestSupport.newAccessRequest()

        it("""
            encode oauth exception
        """.trimIndent()) {
            val error = object : OAuthException("test-code", "test-description") {
                override fun statusCode(): Int = 400
            }
            val response: HttpSupport.MapHttpResponseWriter = HttpSupport.response()

            assertThatCode {
                provider.encodeAccessError(response, request, error)
            }.doesNotThrowAnyException()

            response.assertStatus(400)
            response.assertHeader("Content-Type", "application/json;charset=UTF-8")
            response.getBodyAsJsonMap().run {
                listOf(
                        Pair("status_code", "400"),
                        Pair("error_description", "test-description"),
                        Pair("error", "test-code")
                ).forEach { pair ->
                    assertThat(this).containsEntry(pair.first, pair.second)
                }
            }
        }

        it("""
            encode generic exception
        """.trimIndent()) {
            val error = RuntimeException("generic")
            val response: HttpSupport.MapHttpResponseWriter = HttpSupport.response()

            assertThatCode {
                provider.encodeAccessError(response, request, error)
            }.doesNotThrowAnyException()

            response.assertStatus(500)
            response.assertHeader("Content-Type", "application/json;charset=UTF-8")
            response.getBodyAsJsonMap().run {
                listOf(
                        Pair("status_code", "500"),
                        Pair("error_description", "generic"),
                        Pair("error", "server_error")
                ).forEach { pair ->
                    assertThat(this).containsEntry(pair.first, pair.second)
                }
            }
        }
    }
})