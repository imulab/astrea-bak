package io.imulab.astrea.handler

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.setCodeAsQuery
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.error.CodeChallengeException
import io.imulab.astrea.error.RequestParameterInvalidValueException
import io.imulab.astrea.handler.flow.OAuthPkceHandler
import io.imulab.astrea.handler.validator.DisallowPkceValidator
import io.imulab.astrea.handler.validator.PkceValidator
import io.imulab.astrea.handler.validator.PlainPkceValidator
import io.imulab.astrea.handler.validator.S256PkceValidator
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.mockito.Mockito.mock
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthPkceHandlerSpec : Spek({

    val memoryStorage = MemoryStorage()
    val supportAllValidator: PkceValidator = PkceValidator.with(PlainPkceValidator, S256PkceValidator())
    val defaultVerifier = "A_VERY_LONG_WORD_DEFINITELY_OVER_THIRTY_TWO_CHARACTERS"

    describe("with support all validators") {
        val handler = OAuthPkceHandler(
                authorizeCodeStrategy = TokenSupport.AuthorizeCode.defaultStrategy,
                pkceValidator = supportAllValidator,
                pkceSessionStorage = memoryStorage,
                allowPlainChallengeMethod = true
        )

        describe("correct flow") {

            val flow = Flow(verifierPlain = defaultVerifier).also {
                memoryStorage.createAuthorizeCodeSession(it.code, mock(OAuthRequest::class.java))
            }

            it("""
                should handle authorize request
            """.trimIndent()) {
                flow.makeAuthorizeRequest { authorizeRequest, authorizeResponse ->
                    assertThatCode {
                        handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                    }.doesNotThrowAnyException()
                }
            }

            it("""
                should handle access request
            """.trimIndent()) {
                flow.makeAccessRequest { accessRequest ->
                    assertThat(handler.supports(accessRequest)).isTrue()
                    assertThatCode {
                        handler.handleAccessRequest(accessRequest)
                    }.doesNotThrowAnyException()
                }
            }

            afterGroup {
                memoryStorage.clearAll()
            }
        }

        describe("failure mode") {

            describe("incorrect verifier") {

                val flow = Flow(verifierPlain = defaultVerifier).also {
                    memoryStorage.createAuthorizeCodeSession(it.code, mock(OAuthRequest::class.java))
                }
                val badVerifier: String = TokenSupport.Pkce.challengeAndVerifier(verifier = defaultVerifier + "modified").second

                it("""
                    should handle authorize request
                """.trimIndent()) {
                    flow.makeAuthorizeRequest { authorizeRequest, authorizeResponse ->
                        assertThatCode {
                            handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                        }.doesNotThrowAnyException()
                    }
                }

                it("""
                    should reject access request due to bad code challenge
                """.trimIndent()) {
                    flow.makeAccessRequest(badVerifier) { accessRequest ->
                        assertThat(handler.supports(accessRequest)).isTrue()
                        assertThatExceptionOfType(CodeChallengeException::class.java)
                                .isThrownBy { handler.handleAccessRequest(accessRequest) }
                    }
                }

                afterGroup {
                    memoryStorage.clearAll()
                }
            }

            describe("insufficient entropy") {
                val flow = Flow(verifierPlain = "very-short").also {
                    memoryStorage.createAuthorizeCodeSession(it.code, mock(OAuthRequest::class.java))
                }

                it("""
                    should handle authorize request
                """.trimIndent()) {
                    flow.makeAuthorizeRequest { authorizeRequest, authorizeResponse ->
                        assertThatCode {
                            handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                        }.doesNotThrowAnyException()
                    }
                }

                it("""
                    should reject access request due to insufficient code verifier entropy
                """.trimIndent()) {
                    flow.makeAccessRequest { accessRequest ->
                        assertThat(handler.supports(accessRequest)).isTrue()
                        assertThatExceptionOfType(RequestParameterInvalidValueException.CodeVerifierInsufficientEntropy::class.java)
                                .isThrownBy { handler.handleAccessRequest(accessRequest) }
                    }
                }

                afterGroup {
                    memoryStorage.clearAll()
                }
            }
        }
    }

    describe("with only s256 validator") {
        val handler = OAuthPkceHandler(
                authorizeCodeStrategy = TokenSupport.AuthorizeCode.defaultStrategy,
                pkceValidator = PkceValidator.with(DisallowPkceValidator(CodeChallengeMethod.Plain), S256PkceValidator()),
                pkceSessionStorage = memoryStorage,
                allowPlainChallengeMethod = false
        )

        it("""
            plain method should be rejected
        """.trimIndent()) {
            val flow = Flow(method = CodeChallengeMethod.Plain, verifierPlain = defaultVerifier)

            flow.makeAuthorizeRequest(method = CodeChallengeMethod.Plain) { authorizeRequest, authorizeResponse ->
                assertThatExceptionOfType(RequestParameterInvalidValueException.UnsupportedCodeChallengeMethod::class.java)
                        .isThrownBy { handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse) }
            }
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

}) {
    private class Flow(val code: AuthorizeCode = TokenSupport.AuthorizeCode.new(),
                       val method: CodeChallengeMethod = CodeChallengeMethod.S256,
                       verifierPlain: String = "") {

        private val challengeAndVerifier = TokenSupport.Pkce.challengeAndVerifier(this.method, verifierPlain)

        fun getChallenge(): String = challengeAndVerifier.first

        fun getVerifier(): String = challengeAndVerifier.second

        fun makeAuthorizeRequest(challenge: String = getChallenge(),
                                 method: CodeChallengeMethod = CodeChallengeMethod.S256,
                                 callback: (AuthorizeRequest, AuthorizeResponse) -> Unit) {
            val authorizeRequest = RequestSupport.newAuthorizeRequest(form = mapOf(
                    PARAM_CODE_CHALLENGE to listOf(challenge),
                    PARAM_CODE_CHALLENGE_METHOD to listOf(method.specValue)
            ), client = ClientSupport.foo(isPublic = true))
            val authorizeResponse = DefaultAuthorizeResponse().also {
                it.setCodeAsQuery(code.code)
            }
            callback(authorizeRequest, authorizeResponse)
        }

        fun makeAccessRequest(verifier: String = getVerifier(), callback: (AccessRequest) -> Unit) {
            val accessRequest = RequestSupport.newAccessRequest(form = mapOf(
                    PARAM_CODE to listOf(code.code),
                    PARAM_CODE_VERIFIER to listOf(verifier)
            ), session = DefaultSession(), client = ClientSupport.foo(isPublic = true))
            callback(accessRequest)
        }
    }
}