package io.imulab.astrea.support

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.Scope
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.extension.setScopes
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.request.impl.DefaultAccessRequest
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.spi.http.UrlValues
import io.imulab.astrea.token.strategy.impl.HmacAuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.impl.HmacRefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtAccessTokenStrategy
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import java.security.Key
import java.time.LocalDateTime

object TokenSupport {

    val ISSUER = "astrea"

    object AccessToken {

        val defaultStrategy = JwtAccessTokenStrategy(
                jwtRs256 = JwtRs256(KeySupport.defaultJwk),
                issuer = ISSUER
        )

        fun new(form: UrlValues = emptyMap(),
                scopes: List<Scope> = listOf("foo"),
                grantedScopes: List<Scope> = listOf("foo"),
                client: OAuthClient = ClientSupport.foo(),
                jwtClaims: JwtClaims = JwtClaims().also { it.setScopes(grantedScopes) },
                jwtHeaders: Map<String, String> = emptyMap(),
                expiry: LocalDateTime = LocalDateTime.now().plusHours(1)
        ): io.imulab.astrea.token.AccessToken {
            return defaultStrategy.generateNewAccessToken(DefaultAccessRequest.Builder().also { b ->
                b.setForm(form)
                b.addScopes(*scopes.toTypedArray())
                b.addGrantedScopes(*grantedScopes.toTypedArray())
                b.client = client
                b.session = DefaultJwtSession(claims = jwtClaims, headers = jwtHeaders).also {
                    it.setExpiry(TokenType.AccessToken, expiry)
                }
            }.build())
        }
    }

    object RefreshToken {

        val defaultStrategy = HmacRefreshTokenStrategy(hmac = HmacSha256(secretKey = KeySupport.defaultSecretKey))

        fun new(form: UrlValues = emptyMap(),
                scopes: List<Scope> = listOf("foo"),
                grantedScopes: List<Scope> = listOf("foo"),
                client: OAuthClient = ClientSupport.foo(),
                expiry: LocalDateTime = LocalDateTime.now().plusDays(1)): io.imulab.astrea.token.RefreshToken {
            return defaultStrategy.generateNewRefreshToken(DefaultAccessRequest.Builder().also { b ->
                b.setForm(form)
                b.addScopes(*scopes.toTypedArray())
                b.addGrantedScopes(*grantedScopes.toTypedArray())
                b.client = client
                b.session = DefaultSession().also {
                    it.setExpiry(TokenType.RefreshToken, expiry)
                }
            }.build())
        }
    }

    object AuthorizeCode {

        val defaultStrategy = HmacAuthorizeCodeStrategy(hmac = HmacSha256(secretKey = KeySupport.defaultSecretKey))

        fun new(form: UrlValues = emptyMap(),
                responseTypes: Set<ResponseType> = setOf(ResponseType.Code),
                grantedScopes: List<Scope> = listOf("foo"),
                redirectUri: String = ClientSupport.OPEN_CALLBACK,
                client: OAuthClient = ClientSupport.foo(),
                state: String = "12345678"): io.imulab.astrea.token.AuthorizeCode {
            return defaultStrategy.generateNewAuthorizeCode(DefaultAuthorizeRequest.Builder().also {
                it.responseTypes.addAll(responseTypes)
                it.grantedScopes.addAll(grantedScopes)
                it.redirectUri = redirectUri
                it.state = state
                it.setForm(form)
                it.client = client
                it.session = DefaultSession()
            }.build())
        }
    }

    fun customJwt(issuer: String = ISSUER,
                  subject: String = "developer",
                  audience: String = "test-case",
                  claimsModifier: (JwtClaims) -> Unit = {},
                  keyId: String = KeySupport.defaultJwk.keyId,
                  key: Key = KeySupport.defaultJwk.rsaPrivateKey,
                  alg: String = AlgorithmIdentifiers.RSA_USING_SHA256): String {
        return customJws(issuer, subject, audience, claimsModifier, keyId, key, alg).compactSerialization
    }

    fun customJws(issuer: String = ISSUER,
                  subject: String = "developer",
                  audience: String = "test-case",
                  claimsModifier: (JwtClaims) -> Unit = {},
                  keyId: String = KeySupport.defaultJwk.keyId,
                  key: Key = KeySupport.defaultJwk.rsaPrivateKey,
                  alg: String = AlgorithmIdentifiers.RSA_USING_SHA256): JsonWebSignature {
        return JsonWebSignature().also { jws ->
            jws.payload = JwtClaims().also {
                it.setGeneratedJwtId()
                it.issuer = issuer
                it.subject = subject
                it.setAudience(audience)
                it.setIssuedAtToNow()
                it.setExpirationTimeMinutesInTheFuture(10f)
            }.also(claimsModifier).toJson()
            jws.keyIdHeaderValue = keyId
            jws.key = key
            jws.algorithmHeaderValue = alg
        }
    }
}