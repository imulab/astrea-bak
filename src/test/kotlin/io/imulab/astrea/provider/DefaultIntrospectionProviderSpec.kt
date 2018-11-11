package io.imulab.astrea.provider

import io.imulab.astrea.domain.PARAM_TOKEN
import io.imulab.astrea.domain.PARAM_TOKEN_TYPE_HINT
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.TokenTypeHint
import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.support.HttpSupport
import io.imulab.astrea.support.ProviderSupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.jose4j.jwt.JwtClaims
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.Suite
import org.spekframework.spek2.style.specification.describe
import java.util.*

object DefaultIntrospectionProviderSpec : Spek({

    val memoryStorage = MemoryStorage()
    val provider: IntrospectionProvider = ProviderSupport.Introspect.forDefaultTest(memoryStorage)

    describe("basic auth client introspect successfully") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToInspect = flow.generateAccessToken().token
            flow.makeRequestWithBasicAuthorization(
                    username = "foo", password = "s3cret", hint = TokenTypeHint.HintsAccessToken)
        }

        flow.expectSuccess(this, provider)

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("completes introspection without wrong hint") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToInspect = flow.generateAccessToken().token
            flow.makeRequestWithBasicAuthorization(
                    username = "foo", password = "s3cret", hint = TokenTypeHint.HintsRefreshToken)
        }

        flow.expectSuccess(this, provider)

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("jwt auth client introspect successfully") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToInspect = flow.generateAccessToken().token
            flow.makeRequestWithBearerToken(token = flow.generateAccessToken().token)
        }

        flow.expectSuccess(this, provider)

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("refresh token introspects successfully") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToInspect = flow.generateRefreshToken().token
            flow.makeRequestWithBearerToken(token = flow.generateAccessToken().token)
        }

        flow.expectSuccess(this, provider) { introspectResponse ->
            introspectResponse.run {
                assertThat(isActive()).isTrue()
                assertThat(getAccessRequest()).isNotNull
                assertThat(getTokenType()).isEqualTo(TokenType.RefreshToken)
                assertThat(getAccessRequest()).run {
                    extracting { it?.getSession() }
                            .isNotNull()
                    extracting { it?.getGrantedScopes() }
                            .isNotNull()
                            .asList()
                            .contains("foo")
                }
            }
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("basic auth should fail with invalid secret") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToInspect = flow.generateAccessToken().token
            flow.makeRequestWithBasicAuthorization(
                    username = "foo", password = "invalid", hint = TokenTypeHint.HintsAccessToken)
        }

        flow.expectFailAtHandleRequest(this, provider, InvalidClientException.AuthenticationFailed::class.java)

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("jwt auth should fail with invalid jwt") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToInspect = flow.generateAccessToken().token
            flow.makeRequestWithBearerToken(token = "invalid-jwt")
        }

        flow.expectFailAtHandleRequest(this, provider, InvalidClientException.AuthenticationFailed::class.java)

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("should return nothing if there's no record") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            memoryStorage.clearAll()
            // use refresh token here. because we configured a jwt inspector for access token, it will always be 'found'.
            flow.tokenToInspect = flow.generateRefreshToken(save = false).token
            flow.makeRequestWithBearerToken(token = flow.generateAccessToken().token)
        }

        flow.expectSuccess(this, provider) { introspectResponse ->
            assertThat(introspectResponse.isActive()).isFalse()
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

}) {

    private class Flow(val memoryStorage: MemoryStorage) {

        var tokenToInspect: String? = null
        var request: HttpRequestReader? = null
        var introspectRequest: IntrospectRequest? = null
        var introspectResponse: IntrospectResponse? = null

        fun generateAccessToken(request: OAuthRequest = RequestSupport.newAccessRequest(), save: Boolean = true): AccessToken {
            return TokenSupport.AccessToken.new().also {
                if (save)
                    memoryStorage.createAccessTokenSession(it, request)
            }
        }

        fun generateRefreshToken(request: OAuthRequest = RequestSupport.newAccessRequest(), save: Boolean = true): RefreshToken {
            return TokenSupport.RefreshToken.new().also {
                if (save)
                    memoryStorage.createRefreshTokenSession(it, request)
            }
        }

        fun makeRequestWithBasicAuthorization(username: String, password: String, hint: TokenTypeHint? = null): HttpRequestReader {
            checkNotNull(tokenToInspect)
            request = HttpSupport.request(
                    method = "POST",
                    headers = mapOf(
                            "Authorization" to "Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("$username:$password".toByteArray())
                    ),
                    forms = mutableMapOf(
                            PARAM_TOKEN to listOf(tokenToInspect!!)
                    ).also {
                        if (hint != null)
                            it[PARAM_TOKEN_TYPE_HINT] = listOf(hint.specValue)
                    }
            )
            return request!!
        }

        fun makeRequestWithBearerToken(token: String, hint: TokenTypeHint? = null): HttpRequestReader {
            checkNotNull(tokenToInspect)
            request = HttpSupport.request(
                    method = "POST",
                    headers = mapOf(
                            "Authorization" to "Bearer $token"
                    ),
                    forms = mutableMapOf(
                            PARAM_TOKEN to listOf(tokenToInspect!!)
                    ).also {
                        if (hint != null)
                            it[PARAM_TOKEN_TYPE_HINT] = listOf(hint.specValue)
                    }
            )
            return request!!
        }

        fun expectSuccess(suite: Suite, provider: IntrospectionProvider, assertions: ((IntrospectResponse) -> Unit)? = null) {
            suite.apply {
                it("should handle request") {
                    assertThat(this@Flow.request).isNotNull
                    assertThatCode {
                        this@Flow.introspectRequest = provider.newIntrospectRequest(this@Flow.request!!, DefaultJwtSession(claims = JwtClaims()))
                    }.doesNotThrowAnyException()
                }

                it("should generateAccessToken response") {
                    assertThat(this@Flow.introspectRequest).isNotNull
                    assertThatCode {
                        this@Flow.introspectResponse = provider.newIntrospectResponse(this@Flow.introspectRequest!!)
                    }.doesNotThrowAnyException()
                }

                it("should have returned token info") {
                    assertThat(this@Flow.introspectResponse).isNotNull
                    this@Flow.introspectResponse!!.run {
                        if (assertions != null)
                            assertions(this)
                        else {
                            assertThat(isActive()).isTrue()
                            assertThat(getAccessRequest()).isNotNull
                            assertThat(getTokenType()).isEqualTo(TokenType.AccessToken)
                            assertThat(getAccessRequest()).run {
                                extracting { it?.getSession() }
                                        .isNotNull()
                                extracting { it?.getGrantedScopes() }
                                        .isNotNull()
                                        .asList()
                                        .contains("foo")
                                extracting { it?.getSession()?.getExpiry(TokenType.AccessToken) }
                                        .isNotNull()
                            }
                        }
                    }
                }
            }
        }

        fun expectFailAtHandleRequest(suite: Suite, provider: IntrospectionProvider, errorClass: Class<out Throwable>) {
            suite.apply {
                it("should fail to handle request") {
                    assertThat(this@Flow.request).isNotNull
                    assertThatExceptionOfType(errorClass).isThrownBy {
                        provider.newIntrospectRequest(this@Flow.request!!, DefaultJwtSession(claims = JwtClaims()))
                    }
                }
            }
        }
    }
}