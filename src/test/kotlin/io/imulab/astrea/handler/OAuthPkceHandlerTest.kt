package io.imulab.astrea.handler

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.crypt.hash.ShaHasher
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.setCodeAsQuery
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAccessRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.error.CodeChallengeException
import io.imulab.astrea.error.RequestParameterInvalidValueException
import io.imulab.astrea.handler.impl.OAuthPkceHandler
import io.imulab.astrea.handler.validator.DisallowPkceValidator
import io.imulab.astrea.handler.validator.PkceValidator
import io.imulab.astrea.handler.validator.PlainPkceValidator
import io.imulab.astrea.handler.validator.S256PkceValidator
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.impl.HmacAuthorizeCodeStrategy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.function.Executable
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.Mockito.mock
import java.nio.charset.StandardCharsets
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class OAuthPkceHandlerTest {

    @ParameterizedTest(name = "#{index}: {0}")
    @MethodSource("params")
    fun testPkce(
            @Suppress("UNUSED_PARAMETER") testName: String,
            handler: OAuthPkceHandler,
            challenge: String,
            verifier: String,
            method: CodeChallengeMethod,
            stageOneThrows: Class<Throwable>? = null,
            stageTwoThrows: Class<Throwable>? = null
    ) {
        val code = TestContext.authorizeCodeStrategy.generateNewAuthorizeCode(mock(AuthorizeRequest::class.java)).code

        val authorizeRequest = DefaultAuthorizeRequest.Builder().also {
            it.setForm(PARAM_CODE_CHALLENGE, challenge)
            it.setForm(PARAM_CODE_CHALLENGE_METHOD, method.specValue)
            it.client = TestContext.client
            it.state = "1234567890"
        }.build() as AuthorizeRequest
        val authorizeResponse = DefaultAuthorizeResponse().also { it.setCodeAsQuery(code) }

        val stageOne = Executable { handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse) }
        if (stageOneThrows != null) {
            assertThrows(stageOneThrows, stageOne)
            return
        } else
            assertDoesNotThrow(stageOne)

        val accessRequest = DefaultAccessRequest.Builder().also {
            it.addGrantType(GrantType.AuthorizationCode)
            it.client = TestContext.client
            it.setForm(PARAM_CODE, code)
            it.setForm(PARAM_CODE_VERIFIER, verifier)
            it.session = DefaultSession()
        }.build() as AccessRequest

        assertTrue(handler.supports(accessRequest))

        val stageTwo = Executable { handler.handleAccessRequest(accessRequest) }
        if (stageTwoThrows != null)
            assertThrows(stageTwoThrows, stageTwo)
        else
            assertDoesNotThrow(stageTwo)
    }

    @AfterEach
    fun cleanUp() {
        TestContext.memoryStorage.clearAll()
    }

    companion object {
        @JvmStatic
        fun params() = listOf(
                Arguments.of(
                        "correct challenge and verifier should pass",
                        OAuthPkceHandler(
                                authorizeCodeStrategy = TestContext.authorizeCodeStrategy,
                                allowPlainChallengeMethod = true,
                                pkceSessionStorage = TestContext.memoryStorage,
                                pkceValidator = TestContext.supportAllValidator
                        ),
                        challengeB64(CodeChallengeMethod.S256, "A_VERY_LONG_WORD_DEFINITELY_OVER_THIRTY_TWO_CHARACTERS"),
                        verifierB64("A_VERY_LONG_WORD_DEFINITELY_OVER_THIRTY_TWO_CHARACTERS"),
                        CodeChallengeMethod.S256,
                        null,
                        null
                ),

                Arguments.of(
                        "incorrect verifier should be rejected",
                        OAuthPkceHandler(
                                authorizeCodeStrategy = TestContext.authorizeCodeStrategy,
                                allowPlainChallengeMethod = true,
                                pkceSessionStorage = TestContext.memoryStorage,
                                pkceValidator = TestContext.supportAllValidator
                        ),
                        challengeB64(CodeChallengeMethod.S256, "A_VERY_LONG_WORD_DEFINITELY_OVER_THIRTY_TWO_CHARACTERS"),
                        verifierB64("A_VERY_LONG_WORD_DEFINITELY_OVER_THIRTY_TWO_CHARACTERS_MODIFIED"),
                        CodeChallengeMethod.S256,
                        null,
                        CodeChallengeException::class.java
                ),

                Arguments.of(
                        "plain method should be rejected when not supported",
                        OAuthPkceHandler(
                                authorizeCodeStrategy = TestContext.authorizeCodeStrategy,
                                allowPlainChallengeMethod = false,
                                pkceSessionStorage = TestContext.memoryStorage,
                                pkceValidator = TestContext.disallowPlainValidator
                        ),
                        challengeB64(CodeChallengeMethod.Plain, "A_VERY_LONG_WORD_DEFINITELY_OVER_THIRTY_TWO_CHARACTERS"),
                        verifierB64("A_VERY_LONG_WORD_DEFINITELY_OVER_THIRTY_TWO_CHARACTERS"),
                        CodeChallengeMethod.Plain,
                        RequestParameterInvalidValueException.UnsupportedCodeChallengeMethod::class.java,
                        null
                ),

                Arguments.of(
                        "insufficient entropy should be rejected",
                        OAuthPkceHandler(
                                authorizeCodeStrategy = TestContext.authorizeCodeStrategy,
                                allowPlainChallengeMethod = true,
                                pkceSessionStorage = TestContext.memoryStorage,
                                pkceValidator = TestContext.supportAllValidator
                        ),
                        challengeB64(CodeChallengeMethod.S256, "LT_32"),
                        verifierB64("LT_32"),
                        CodeChallengeMethod.S256,
                        null,
                        RequestParameterInvalidValueException.CodeVerifierInsufficientEntropy::class.java
                )
        )

        private fun challengeB64(method: CodeChallengeMethod, verifier: String): String {
            return TestContext.encoder.encodeToString(
                    when (method) {
                        CodeChallengeMethod.Plain -> verifier.toByteArray(StandardCharsets.UTF_8)
                        CodeChallengeMethod.S256 -> ShaHasher.usingSha256().hash(verifier.toByteArray(StandardCharsets.UTF_8))
                    }
            )
        }

        private fun verifierB64(verifier: String): String {
            return TestContext.encoder.encodeToString(verifier.toByteArray(StandardCharsets.UTF_8))
        }
    }

    private object TestContext {

        val client = DefaultOAuthClient(
                id = "public-client",
                secret = ByteArray(0),
                public = true
        )

        val decoder by lazy { Base64.getUrlDecoder() }

        val encoder by lazy { Base64.getUrlEncoder().withoutPadding() }

        val hmacKey: SecretKey by lazy {
            KeyGenerator.getInstance("AES").generateKey()
        }

        val authorizeCodeStrategy by lazy {
            // we are not using its generate functions, so we don't care about the actual hmac
            HmacAuthorizeCodeStrategy(hmac = HmacSha256(secretKey = hmacKey))
        }

        val memoryStorage by lazy { MemoryStorage() }

        val supportAllValidator by lazy {
            PkceValidator.with(PlainPkceValidator, S256PkceValidator())
        }

        val disallowPlainValidator by lazy {
            PkceValidator.with(DisallowPkceValidator(CodeChallengeMethod.Plain), S256PkceValidator())
        }
    }
}