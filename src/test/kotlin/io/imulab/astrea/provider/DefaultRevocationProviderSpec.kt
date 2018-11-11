package io.imulab.astrea.provider

import io.imulab.astrea.domain.PARAM_TOKEN
import io.imulab.astrea.domain.PARAM_TOKEN_TYPE_HINT
import io.imulab.astrea.domain.TokenTypeHint
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.request.RevocationRequest
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.support.*
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.util.*

object DefaultRevocationProviderSpec: Spek({

    val memoryStorage = MemoryStorage()
    val provider: RevocationProvider = ProviderSupport.Revocation.forDefaultTest(memoryStorage)

    describe("revoking non-existing token should fail gracefully") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToRevoke = flow.generateAccessToken(save = false).token
            flow.makeRequestWithBasicAuthorization("foo", "s3cret")
        }

        it("""
            should have thrown an internal exception indicating revocation failed
        """.trimIndent()) {
            assertThat(flow.request).isNotNull
            assertThatCode {
                provider.revoke(flow.request!!)
            }.extracting { it.javaClass.simpleName }.isEqualTo("RevocationDidNotSucceedException")
        }

        afterGroup { memoryStorage.clearAll() }
    }

    describe("revoking a token that does not belong to requester should fail") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToRevoke = TokenSupport.AccessToken.new(client = ClientSupport.bar()).also {
                memoryStorage.createAccessTokenSession(it, RequestSupport.newAccessRequest(client = ClientSupport.bar()))
            }.token
            flow.makeRequestWithBasicAuthorization("foo", "s3cret")
        }

        it("""
            should spot mismatched identity
        """.trimIndent()) {
            assertThat(flow.request).isNotNull
            assertThatExceptionOfType(InvalidGrantException.ClientIdentityMismatch::class.java)
                    .isThrownBy {
                        provider.revoke(flow.request!!)
                    }
        }

        afterGroup { memoryStorage.clearAll() }
    }

    describe("revoke an owned token should pass") {
        val flow = Flow(memoryStorage)

        beforeGroup {
            flow.tokenToRevoke = flow.generateAccessToken().token
            flow.makeRequestWithBasicAuthorization("foo", "s3cret")
        }

        it("""
            should handle revoke
        """.trimIndent()) {
            assertThat(flow.request).isNotNull
            assertThatCode {
                provider.revoke(flow.request!!)
            }.doesNotThrowAnyException()
        }

        it("""
            code should have disappeared from storage
        """.trimIndent()) {
            assertThatExceptionOfType(InvalidGrantException.NotFound::class.java)
                    .isThrownBy {
                        flow.tokenToRevoke!!.let {
                            TokenSupport.AccessToken.defaultStrategy.fromRaw(it)
                        }.let {
                            memoryStorage.getAccessTokenSession(it)
                        }
                    }
        }

        afterGroup { memoryStorage.clearAll() }
    }

}) {

    private class Flow(private val memoryStorage: MemoryStorage) {
        var tokenToRevoke: String? = null
        var request: HttpRequestReader? = null
        var revokeRequest: RevocationRequest? = null

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
            checkNotNull(tokenToRevoke)
            request = HttpSupport.request(
                    method = "POST",
                    headers = mapOf(
                            "Authorization" to "Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("$username:$password".toByteArray())
                    ),
                    forms = mutableMapOf(
                            PARAM_TOKEN to listOf(tokenToRevoke!!)
                    ).also {
                        if (hint != null)
                            it[PARAM_TOKEN_TYPE_HINT] = listOf(hint.specValue)
                    }
            )
            return request!!
        }
    }
}