package io.imulab.astrea.provider

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.setScopes
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.error.OAuthException
import io.imulab.astrea.error.RequestParameterInvalidValueException
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.support.*
import org.apache.http.client.utils.URIBuilder
import org.assertj.core.api.Assertions.*
import org.jose4j.jwt.consumer.InvalidJwtException
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.lang.RuntimeException

object DefaultAuthorizeProviderSpec : Spek({

    describe("provider") {

        val provider: AuthorizeProvider = ProviderSupport.Authorize.forTestProvider()

        it("""
            should handle new oauth request when it's proper
        """.trimIndent()) {
            val request: HttpRequestReader = HttpSupport.request(
                    method = "POST",
                    forms = mapOf(
                            PARAM_CLIENT_ID to listOf(ClientSupport.foo().getId()),
                            PARAM_REDIRECT_URI to listOf(ClientSupport.OPEN_CALLBACK),
                            PARAM_SCOPE to listOf("foo"),
                            PARAM_RESPONSE_TYPE to listOf(ResponseType.Code.specValue),
                            PARAM_STATE to listOf("12345678")
                    )
            )
            var authorizeRequest: AuthorizeRequest? = null
            assertThatCode {
                authorizeRequest = provider.newAuthorizeRequest(request)
            }.doesNotThrowAnyException()

            assertThat(authorizeRequest).isNotNull
            authorizeRequest!!.run {
                assertThat(this.getId()).isNotEmpty()
                assertThat(this.getClient().getId()).isEqualTo(ClientSupport.foo().getId())
                assertThat(this.isRedirectUriValid()).isTrue()
                assertThat(this.getRedirectUri()).isEqualTo(ClientSupport.OPEN_CALLBACK)
                assertThat(this.getRequestScopes()).contains("foo")
                assertThat(this.getGrantedScopes()).isEmpty()
                assertThat(this.getState()).isEqualTo("12345678")
                assertThat(this.getSession()).isNull()
            }
        }

        it("""
            should handle new oidc request whern it's proper
        """.trimIndent()) {
            val request: HttpRequestReader = HttpSupport.request(forms = mapOf(
                    PARAM_CLIENT_ID to listOf(ClientSupport.bar().getId()),
                    PARAM_REDIRECT_URI to listOf(ClientSupport.OPEN_CALLBACK),
                    PARAM_SCOPE to listOf("foo $SCOPE_OPENID"),
                    PARAM_RESPONSE_TYPE to listOf("${ResponseType.Code.specValue} ${ResponseType.IdToken.specValue}"),
                    PARAM_STATE to listOf("12345678"),
                    PARAM_REQUEST to listOf(TokenSupport.customJwt(
                            issuer = ClientSupport.bar().getId(),
                            audience = "test",
                            claimsModifier = { jwtClaims ->
                                jwtClaims.setScopes(listOf("email"))
                            }
                    ))
            ))

            var authorizeRequest: AuthorizeRequest? = null
            assertThatCode {
                authorizeRequest = provider.newAuthorizeRequest(request)
            }.doesNotThrowAnyException()

            assertThat(authorizeRequest).isNotNull
            authorizeRequest!!.run {
                assertThat(this.getId()).isNotEmpty()
                assertThat(this.getClient().getId()).isEqualTo(ClientSupport.bar().getId())
                assertThat(this.isRedirectUriValid()).isTrue()
                assertThat(this.getRedirectUri()).isEqualTo(ClientSupport.OPEN_CALLBACK)
                assertThat(this.getRequestScopes()).contains("foo", "email", SCOPE_OPENID)
                assertThat(this.getResponseTypes()).contains(ResponseType.Code, ResponseType.IdToken)
                assertThat(this.getState()).isEqualTo("12345678")
                assertThat(this.getGrantedScopes()).isEmpty()
                assertThat(this.getSession()).isNull()
            }
        }

        it("""
            oauth request with unregistered redirection uri should fail
        """.trimIndent()) {
            val request: HttpRequestReader = HttpSupport.request(
                    method = "POST",
                    forms = mapOf(
                            PARAM_CLIENT_ID to listOf(ClientSupport.foo().getId()),
                            PARAM_REDIRECT_URI to listOf("http://this-is-invalid.com/callback"),
                            PARAM_SCOPE to listOf("foo"),
                            PARAM_RESPONSE_TYPE to listOf(ResponseType.Code.specValue),
                            PARAM_STATE to listOf("12345678")
                    )
            )
            assertThatExceptionOfType(RequestParameterInvalidValueException.RougeRedirectUri::class.java)
                    .isThrownBy { provider.newAuthorizeRequest(request) }
        }

        it("""
            oauth request with invalid issuer (<> client_id) should be rejected
        """.trimIndent()) {
            val request: HttpRequestReader = HttpSupport.request(forms = mapOf(
                    PARAM_CLIENT_ID to listOf(ClientSupport.bar().getId()),
                    PARAM_REDIRECT_URI to listOf(ClientSupport.OPEN_CALLBACK),
                    PARAM_SCOPE to listOf("foo $SCOPE_OPENID"),
                    PARAM_RESPONSE_TYPE to listOf("${ResponseType.Code.specValue} ${ResponseType.IdToken.specValue}"),
                    PARAM_STATE to listOf("12345678"),
                    PARAM_REQUEST to listOf(TokenSupport.customJwt(
                            issuer = "not-equal-to-client-id",
                            audience = "test",
                            claimsModifier = { jwtClaims ->
                                jwtClaims.setScopes(listOf("email"))
                            }
                    ))
            ))

            assertThatExceptionOfType(InvalidJwtException::class.java)
                    .isThrownBy {
                        provider.newAuthorizeRequest(request)
                    }
        }

        it("""
            oauth client cannot make oidc request
        """.trimIndent()) {
            val request: HttpRequestReader = HttpSupport.request(forms = mapOf(
                    PARAM_CLIENT_ID to listOf(ClientSupport.foo().getId()),
                    PARAM_REDIRECT_URI to listOf(ClientSupport.OPEN_CALLBACK),
                    PARAM_SCOPE to listOf("foo $SCOPE_OPENID"),
                    PARAM_RESPONSE_TYPE to listOf("${ResponseType.Code.specValue} ${ResponseType.IdToken.specValue}"),
                    PARAM_STATE to listOf("12345678"),
                    PARAM_REQUEST to listOf(TokenSupport.customJwt(
                            issuer = ClientSupport.foo().getId(),
                            audience = "test",
                            claimsModifier = { jwtClaims ->
                                jwtClaims.setScopes(listOf("email"))
                            }
                    ))
            ))

            assertThatExceptionOfType(IllegalStateException::class.java)
                    .isThrownBy {
                        provider.newAuthorizeRequest(request)
                    }
        }

    }

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