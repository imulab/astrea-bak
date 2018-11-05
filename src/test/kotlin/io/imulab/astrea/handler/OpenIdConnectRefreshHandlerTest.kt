package io.imulab.astrea.handler

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.DefaultOidcClient
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.getIdToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.DefaultAccessRequest
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.handler.impl.OpenIdConnectRefreshHandler
import io.imulab.astrea.token.strategy.impl.JwtIdTokenStrategy
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class OpenIdConnectRefreshHandlerTest {

    @Test
    fun testIssueRefreshToken() {
        val request = DefaultAccessRequest.Builder().also {
            it.setForm(PARAM_GRANT_TYPE, GrantType.AuthorizationCode.specValue) // because id token strategy looks up in form.
            it.addGrantType(GrantType.RefreshToken)
            it.addGrantedScopes(SCOPE_OPENID)

            it.client = TestContext.defaultClient
            it.session = DefaultOidcSession.Builder().also { s ->
                s.getClaims().run { subject = "imulab" }
            }.build()
        }.build() as AccessRequest

        val response = DefaultAccessResponse().also {
            it.setAccessToken(jwtWithClaims { subject = "for-test-only" })
        }

        TestContext.handler.populateAccessResponse(request, response)

        Assertions.assertTrue(response.getIdToken().isNotEmpty())
    }

    private fun jwtWithClaims(f: JwtClaims.() -> Unit): String =
            JsonWebSignature().also {
                it.payload = JwtClaims().also { c -> c.setGeneratedJwtId(); c.f() }.toJson()
                it.key = TestContext.jwk.rsaPrivateKey
                it.keyIdHeaderValue = TestContext.jwk.keyId
                it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
            }.compactSerialization

    private object TestContext {
        val jwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.use = Use.SIGNATURE
                it.keyId = "test"
            }
        }

        val jwtRs256 = JwtRs256(jwk = jwk)

        val defaultClient = DefaultOidcClient(
                oauth = DefaultOAuthClient(
                        id = "foo",
                        secret = "s3cret".toByteArray(),
                        responseTypes = listOf(ResponseType.Code, ResponseType.IdToken),
                        grantTypes = listOf(GrantType.AuthorizationCode, GrantType.Implicit, GrantType.RefreshToken),
                        scopes = listOf(SCOPE_OPENID, "email", "profile", "foo"),
                        redirectUris = listOf("https://test.com/callback"),
                        public = false
                ),
                jwk = JsonWebKeySet().also { it.addJsonWebKey(jwk) },
                tokenEndpointAuth = AuthMethod.PrivateKeyJwt,
                reqObjSignAlg = SigningAlgorithm.RS256
        )

        val openIdTokenStrategy = JwtIdTokenStrategy(jwtRs256 = jwtRs256, issuer = "foo")

        val handler = OpenIdConnectRefreshHandler(
                openIdConnectTokenStrategy = openIdTokenStrategy
        )
    }
}