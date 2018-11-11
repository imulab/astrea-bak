package io.imulab.astrea.handler

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.getRefreshToken
import io.imulab.astrea.domain.extension.getStateFromQuery
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.handler.flow.OAuthAuthorizeCodeHandler
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthAuthorizeCodeHandlerSpec : Spek({

    val memoryStorage = MemoryStorage()
    val handler = OAuthAuthorizeCodeHandler(
            scopeStrategy = StringEqualityScopeStrategy,
            accessTokenStrategy = TokenSupport.AccessToken.defaultStrategy,
            accessTokenStorage = memoryStorage,
            refreshTokenStrategy = TokenSupport.RefreshToken.defaultStrategy,
            refreshTokenStorage = memoryStorage,
            authorizeCodeStrategy = TokenSupport.AuthorizeCode.defaultStrategy,
            authorizeCodeStorage = memoryStorage)

    describe("correct flow") {
        var cachedCode = ""
        var cachedAccessRequest: AccessRequest? = null

        it("""
            successfully acquire an authorize code
        """.trimIndent()) {
            val authorizeRequest = RequestSupport.newAuthorizeRequest()
            val authorizeResponse = DefaultAuthorizeResponse()

            assertThatCode {
                handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
            }.doesNotThrowAnyException()

            assertThat(authorizeRequest.hasAllResponseTypesBeenHandled()).isTrue()
            assertThat(authorizeResponse.getCode()).isNotBlank()
            assertThat(authorizeResponse.getStateFromQuery()).isEqualTo("1234567890")
            assertThat(authorizeResponse.getQueries().singleValue(PARAM_SCOPE).split(SPACE)).contains("foo", SCOPE_OFFLINE)

            cachedCode = authorizeResponse.getCode()
        }

        it("""
            successfully acquire handle an access request
        """.trimIndent()) {
            check(cachedCode.isNotBlank())

            val accessRequest = RequestSupport.newAccessRequest(form = mapOf(
                    PARAM_CODE to listOf(cachedCode),
                    PARAM_REDIRECT_URI to listOf(ClientSupport.OPEN_CALLBACK)
            ))

            assertThatCode {
                handler.handleAccessRequest(accessRequest)
            }.doesNotThrowAnyException()

            cachedAccessRequest = accessRequest
        }

        it("""
            successfully populate the access response
        """.trimIndent()) {
            checkNotNull(cachedAccessRequest)
            val accessResponse = DefaultAccessResponse()

            assertThatCode {
                handler.populateAccessResponse(cachedAccessRequest!!, accessResponse)
            }.doesNotThrowAnyException()

            assertThat(accessResponse.getAccessToken()).isNotBlank()
            assertThat(accessResponse.getTokenType()).isEqualTo(TokenType.Bearer)
            assertThat(accessResponse.getRefreshToken()).isNotBlank()
            assertThat(accessResponse.getExtra(PARAM_EXPIRES_IN) as Long).isGreaterThan(0)
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("authorize code related failure") {
        var cachedResponse = DefaultAuthorizeResponse()

        beforeEachTest {
            val authorizeRequest = RequestSupport.newAuthorizeRequest()
            assertThatCode {
                handler.handleAuthorizeRequest(authorizeRequest, cachedResponse)
            }.doesNotThrowAnyException()
        }

        it("""
            when authorize code has expired
        """.trimIndent()) {
            check(cachedResponse.getCode().isNotBlank())
            memoryStorage.expireAuthorizeCode(TokenSupport.AuthorizeCode.defaultStrategy.fromRaw(cachedResponse.getCode()).signature)

            val accessRequest = RequestSupport.newAccessRequest(form = mapOf(
                    PARAM_CODE to listOf(cachedResponse.getCode()),
                    PARAM_REDIRECT_URI to listOf(ClientSupport.OPEN_CALLBACK)
            ))

            assertThatExceptionOfType(InvalidGrantException::class.java)
                    .isThrownBy { handler.handleAccessRequest(accessRequest) }
        }

        it("""
            when invalid authorize code is presented
        """.trimIndent()) {
            check(cachedResponse.getCode().isNotBlank())

            val accessRequest = RequestSupport.newAccessRequest(form = mapOf(
                    PARAM_CODE to listOf("invalid_authorize_code"),
                    PARAM_REDIRECT_URI to listOf(ClientSupport.OPEN_CALLBACK)
            ))

            assertThatExceptionOfType(InvalidGrantException::class.java)
                    .isThrownBy { handler.handleAccessRequest(accessRequest) }
        }

        it("""
            when authorize code does not exist
        """.trimIndent()) {
            check(cachedResponse.getCode().isNotBlank())
            memoryStorage.clearAuthorizeCodes()

            val accessRequest = RequestSupport.newAccessRequest(form = mapOf(
                    PARAM_CODE to listOf(cachedResponse.getCode()),
                    PARAM_REDIRECT_URI to listOf(ClientSupport.OPEN_CALLBACK)
            ))

            assertThatExceptionOfType(InvalidGrantException::class.java)
                    .isThrownBy { handler.handleAccessRequest(accessRequest) }
        }

        afterEachTest {
            memoryStorage.clearAll()
        }
    }
})