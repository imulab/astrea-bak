package io.imulab.astrea.provider

import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.error.OAuthException
import io.imulab.astrea.support.HttpSupport
import io.imulab.astrea.support.ProviderSupport
import io.imulab.astrea.support.RequestSupport
import org.assertj.core.api.Assertions.*
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.lang.RuntimeException

object DefaultAccessProviderSpec : Spek({

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