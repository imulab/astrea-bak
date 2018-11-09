package io.imulab.astrea.support

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.DefaultOidcClient
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.*
import io.imulab.astrea.error.InvalidClientException
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.mockito.Mockito
import java.nio.charset.StandardCharsets

object ClientSupport {

    private const val OPEN_SECRET = "s3cret"
    const val OPEN_CALLBACK = "https://test.com/callback"
    private const val OPEN_REQUEST_URI = "https://test.com/request"
    private const val OPEN_JWK_ID = "default-jwk"

    private val passwordEncoder = BCryptPasswordEncoder()

    /**
     * A sample oauth client:
     * - id=foo
     * - non-public
     * - secret=[OPEN_SECRET]
     * - callback=[OPEN_CALLBACK]
     * - scopes=foo bar [SCOPE_OFFLINE]
     * - response_types=[ResponseType.Code] [ResponseType.Token]
     * - grant_types: all enabled
     *
     * Callers can provide modifiers to customize it.
     */
    fun foo(isPublic: Boolean = false,
            redirectModifier: (MutableList<String>) -> Unit = {},
            scopeModifier: (MutableList<Scope>) -> Unit = {},
            responseTypeModifier: (MutableList<ResponseType>) -> Unit = {},
            grantTypeModifier: (MutableList<GrantType>) -> Unit = {}): OAuthClient = DefaultOAuthClient(
            id = "foo",
            secret = passwordEncoder.encode(OPEN_SECRET).toByteArray(StandardCharsets.UTF_8),
            public = isPublic,
            redirectUris = mutableListOf(OPEN_CALLBACK).also(redirectModifier),
            scopes = mutableListOf("foo", "bar", SCOPE_OFFLINE).also(scopeModifier),
            responseTypes = mutableListOf(ResponseType.Code, ResponseType.Token).also(responseTypeModifier),
            grantTypes = mutableListOf(GrantType.AuthorizationCode, GrantType.Implicit,
                    GrantType.ClientCredentials, GrantType.Password,
                    GrantType.RefreshToken).also(grantTypeModifier)
    )

    /**
     * A sample open id connect client:
     * - id=bar
     * - non-public
     * - secret=[OPEN_SECRET]
     * - callback=[OPEN_CALLBACK]
     * - scopes=foo bar [SCOPE_OFFLINE] [SCOPE_OPENID]
     * - response_types=[ResponseType.Code] [ResponseType.Token] [ResponseType.IdToken]
     * - grant_types: all enabled
     * - signing_alg: RS256
     * - token_endpoint_auth: private_key_jwt
     * - jwk: default-jwk
     *
     * Callers can provide modifiers to customize it.
     */
    fun bar(isPublic: Boolean = false,
            redirectModifier: (MutableList<String>) -> Unit = {},
            scopeModifier: (MutableList<Scope>) -> Unit = {},
            responseTypeModifier: (MutableList<ResponseType>) -> Unit = {},
            grantTypeModifier: (MutableList<GrantType>) -> Unit = {},
            requestObjectSigningAlgorithm: SigningAlgorithm = SigningAlgorithm.RS256,
            tokenEndpointAuthMethod: AuthMethod = AuthMethod.PrivateKeyJwt,
            requestUriModifier: (MutableList<String>) -> Unit = {},
            jwks: List<JsonWebKey> = emptyList()): OAuthClient = DefaultOidcClient(
            oauth = DefaultOAuthClient(
                    id = "bar",
                    secret = passwordEncoder.encode(OPEN_SECRET).toByteArray(StandardCharsets.UTF_8),
                    public = isPublic,
                    redirectUris = mutableListOf(OPEN_CALLBACK).also(redirectModifier),
                    scopes = mutableListOf("foo", "bar", SCOPE_OFFLINE, SCOPE_OPENID).also(scopeModifier),
                    responseTypes = mutableListOf(ResponseType.Code,
                            ResponseType.Token, ResponseType.IdToken).also(responseTypeModifier),
                    grantTypes = mutableListOf(GrantType.AuthorizationCode, GrantType.Implicit,
                            GrantType.ClientCredentials, GrantType.Password,
                            GrantType.RefreshToken).also(grantTypeModifier)
            ),
            reqObjSignAlg = requestObjectSigningAlgorithm,
            tokenEndpointAuth = tokenEndpointAuthMethod,
            requestUris = mutableListOf(OPEN_REQUEST_URI).also(requestUriModifier),
            jwk = JsonWebKeySet().also {
                if (jwks.isEmpty())
                    it.addJsonWebKey(KeySupport.defaultJwk)
                else
                    jwks.forEach { jwk -> it.addJsonWebKey(jwk) }
            }
    )

    /**
     * Returns a mocked client manager which can properly
     */
    fun clientManager(vararg clients: OAuthClient): ClientManager {
        val manager = Mockito.mock(ClientManager::class.java)
        clients.forEach { c ->
            Mockito.`when`(manager.getClient(c.getId())).thenReturn(c)
            Mockito.`when`(manager.getClient(Mockito.argThat { id ->
                !clients.map { it.getId() }.contains(id)
            } ?: "")).thenThrow(InvalidClientException.NotFound::class.java)
        }
        return manager
    }
}