package io.imulab.astrea.handler

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.impl.DefaultIntrospectRequest
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.handler.introspect.AccessTokenJwtIntrospectHandler
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.KeySupport
import io.imulab.astrea.support.TokenSupport
import org.assertj.core.api.Assertions.assertThat
import org.mockito.Mockito
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object AccessTokenJwtIntrospectHandlerSpec : Spek({

    val handler = AccessTokenJwtIntrospectHandler(
            jwtRs256 = JwtRs256(KeySupport.defaultJwk),
            issuer = TokenSupport.ISSUER)

    describe("inspect should succeed") {

        it("""
            when provided a proper token
        """.trimIndent()) {
            val accessToken = TokenSupport.AccessToken.new(
                    scopes = listOf("foo", "bar"),
                    grantedScopes = listOf("foo", "bar")
            )
            val resp = handler.introspectToken(DefaultIntrospectRequest.Builder().also {
                it.token = accessToken.token
                it.tokenType = TokenType.AccessToken
                it.client = Mockito.mock(OAuthClient::class.java)
                it.session = DefaultSession()
            }.build())

            assertThat(resp.isActive()).isTrue()
            assertThat(resp.getTokenType()).isEqualTo(TokenType.AccessToken)
            assertThat(resp.getAccessRequest()).isNotNull
            assertThat(resp.getAccessRequest()!!.getGrantedScopes()).contains("foo", "bar")
            assertThat(resp.getAccessRequest()!!.getClient().getId()).isEqualTo(ClientSupport.foo().getId())
        }
    }

    describe("inspect should fail gracefully") {

        it("""
            when provided an invalid token
        """.trimIndent()) {
            val resp = handler.introspectToken(DefaultIntrospectRequest.Builder().also {
                it.token = "bad-formatted-token"
                it.tokenType = TokenType.AccessToken
                it.client = Mockito.mock(OAuthClient::class.java)
                it.session = DefaultSession()
            }.build())

            assertThat(resp.isActive()).isFalse()
            assertThat(resp.getTokenType()).isEqualTo(TokenType.Unknown)
            assertThat(resp.getAccessRequest()).isNull()
        }

        it("""
            when provided a proper token issued by others
        """.trimIndent()) {
            val accessToken = TokenSupport.AccessToken.new(
                    scopes = listOf("foo", "bar"),
                    grantedScopes = listOf("foo", "bar")
            )
            val alternativeHandler = AccessTokenJwtIntrospectHandler(
                    jwtRs256 = JwtRs256(KeySupport.defaultJwk), issuer = "other")
            val resp = alternativeHandler.introspectToken(DefaultIntrospectRequest.Builder().also {
                it.token = accessToken.token
                it.tokenType = TokenType.AccessToken
                it.client = Mockito.mock(OAuthClient::class.java)
                it.session = DefaultSession()
            }.build())

            assertThat(resp.isActive()).isFalse()
            assertThat(resp.getTokenType()).isEqualTo(TokenType.Unknown)
            assertThat(resp.getAccessRequest()).isNull()
        }
    }
})