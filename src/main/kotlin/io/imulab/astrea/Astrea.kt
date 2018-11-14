package io.imulab.astrea

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.auth.*
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.crypt.PasswordEncoder
import io.imulab.astrea.domain.*
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.IntrospectEndpointHandler
import io.imulab.astrea.handler.RevocationEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.handler.flow.*
import io.imulab.astrea.handler.introspect.AccessTokenJwtIntrospectHandler
import io.imulab.astrea.handler.introspect.AccessTokenStorageIntrospectHandler
import io.imulab.astrea.handler.introspect.RefreshTokenStorageIntrospectHandler
import io.imulab.astrea.handler.revoke.AccessTokenStorageRevocationHandler
import io.imulab.astrea.handler.revoke.RefreshTokenStorageRevocationHandler
import io.imulab.astrea.handler.revoke.UnsupportedRevocationHandler
import io.imulab.astrea.handler.validator.*
import io.imulab.astrea.provider.*
import io.imulab.astrea.provider.impl.DefaultAccessProvider
import io.imulab.astrea.provider.impl.DefaultAuthorizeProvider
import io.imulab.astrea.provider.impl.DefaultIntrospectionProvider
import io.imulab.astrea.provider.impl.DefaultRevocationProvider
import io.imulab.astrea.spi.http.HttpClient
import io.imulab.astrea.spi.json.JsonEncoder
import io.imulab.astrea.spi.user.ResourceOwnerAuthenticator
import io.imulab.astrea.token.storage.*
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.IdTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.HmacAuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.impl.HmacRefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtAccessTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtIdTokenStrategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import java.time.Duration
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Astrea: OAuth2 and Open ID Connect Provider.
 *
 * While user can create providers from scratch and compose Astrea manually, it is recommended to prepare a [Astrea.BOM]
 * and call [Astrea.compose] to configure a provider instance.
 */
class Astrea(private val authorizeProvider: AuthorizeProvider,
             private val accessProvider: AccessProvider,
             private val introspectionProvider: IntrospectionProvider,
             private val revocationProvider: RevocationProvider
) : AuthorizeProvider by authorizeProvider,
        AccessProvider by accessProvider,
        IntrospectionProvider by introspectionProvider,
        RevocationProvider by revocationProvider,
        OAuthProvider {

    /**
     * Bill of material for configuring an [Astrea] provider instance.
     *
     * ## Common
     * - [issuer]: Token issuer identifier, used throughout the program. Defaulted to **astrea**.
     * - [jsonEncoder]: SPI interface for encoding JSON values.
     * - [httpClient]: SPI interface for making HTTP requests to retrieve request parameter values.
     * - [scopeStrategy]: Strategy to match two scopes. Default is [HierarchicalScopeStrategy].
     * - [base64Encoder]: Base64 encoder.
     * - [base64Decoder]: Base64 decoder.
     *
     * ## Provider
     * - [minStateEntropy]: Minimum length of the state parameter. Default value is 8.
     * - [minNonceEntropy]: Minimum length of the nonce parameter. Default value is 8.
     * - [clockSkewToleranceInSeconds]: Tolerance for clock configuration difference. Used in validating authorize endpoint OIDC request. Default value is **30**.
     * - [resourceOwnerAuthenticator]: SPI interface for authenticating a resource owner. Not needed if resource owner flow is disabled.
     *
     * ## Authorize Code
     * - [authorizeCodeHmacKey]: Secret key for authorize code HMAC hash function. Default to generating a new AES key.
     * - [authorizeCodeEntropy]: Length of the generated bytes of authorize code. Default to 32.
     * - [authorizeCodeStrategy]: Algorithm for dealing with authorize code. Default is HMAC-SHA256. Override this to provide a different algorithm.
     * - [authorizeCodeStorage]: Storage for authorize code and its sessions.
     * - [authorizeCodeLifespanInSeconds]: Maximum lifespan for authorize code, defaulted to 300 seconds (5 minutes).
     * - [authorizeRequestParamsToStore]: Safe parameters that can be saved to session. All others are discarded. Default is [PARAM_CODE] and [PARAM_REDIRECT_URI].
     *
     * ## Access Token
     * - [accessTokenJwk]: RSA key pair for access token RSA-256 function. Default to generating a new key pair.
     * - [accessTokenStrategy]: Algorithm for dealing with access token. Default is Json Web Token using RSA-256 based. Override this to provide a different algorithm.
     * - [accessTokenStorage]: Storage for access token and its sessions.
     * - [accessTokenLifespanInSeconds]: Maximum lifespan for access token, defaulted to 3600 seconds (1 hour).
     *
     * ## Refresh Token
     * - [refreshTokenHmacKey]: Secret key for refresh token HMAC hash function. Default to generating a new AES key.
     * - [refreshTokenEntropy]: Length of the generated bytes of refresh token. Default to 32.
     * - [refreshTokenStrategy]: Algorithm for dealing with refresh token. Default is HMAC-SHA256. Override this to provide a different algorithm.
     * - [refreshTokenStorage]: Storage for refresh token and its sessions.
     *
     * ## ID Token
     * [idTokenJwk]: RSA key pair for access token RSA-256 function. Default to generating a new key pair.
     * [idTokenStrategy]: Algorithm for dealing with id tokens. Default is Json Web Token using RSA-256 based. Override this to provide a different algorithm.
     * [idTokenLifespanInSeconds]: Maximum lifespan for id token, defaulted to 3600 seconds (1 hour).
     * [oidcRequestStorage]: Storage for Open ID Connect request.
     * [allowOidcLoginPrompt]: Whether to allow OIDC Login Prompt, default is true.
     * [allowOidcNonePrompt]: Whether to allow OIDC None Prompt, default is true.
     * [oidcAuthorizeRequestParamsToStore]: Safe parameters to save to storage. All others are discarded. Default values are [PARAM_GRANT_TYPE], [PARAM_MAX_AGE], [PARAM_PROMPT], [PARAM_ACR_VALUE], [PARAM_ID_TOKEN_HINT], [PARAM_NONCE].
     *
     * ## PKCE
     * [allowPlainChallengeInPkce]: Whether to allow plain challenge in PKCE, default is false
     * [allowS256ChallengeInPkce]: Whether to allow S256 challenge in PKCE, default is true
     * [pkceSessionStorage]: Storage for PKCE sessions.
     * [miniPkceVerifierEntropy]: Minimum length for PKCE verifier bytes. Verifier less than this length will be rejected. Default is 32.
     *
     * ## Client
     * - [tokenEndpointUrl]: URL of the token endpoint. Used to validate audience field of the client authentication JWT.
     * - [clientManager]: SPI interface for managing clients.
     * - [clientPasswordEncoder]: Password encoder for comparing hashed client passwords. Default is [BCryptPasswordEncoder] with hash complexity of 10.
     * - [allowClientHttpBasicAuth]: Whether allow HTTP Basic Authentication for clients. Default is false.
     * - [allowClientSecretPostAuth]: Whether allow HTTP Form Post Authentication for clients. Default is true.
     * - [allowClientPrivateKeyJwtAuth]: Whether allow JWT Private Key Authentication for clients. Default is true.
     * - [allowClientNoneAuth]: Whether allow None Authentication for public clients. Default is true.
     *
     * ## Introspection
     * - [allowStatelessAccessTokenIntrospection]: Whether to enable inspect token as stateless JWT tokens. If false, tokens will be looked up from [accessTokenStorage]. Default is true.
     * - [allowRefreshTokenIntrospection]: Whether to allow inspecting refresh token. Default is true.
     *
     * ## Revocation
     * - [allowRevokeAccessToken]: Whether revoking access token is allowed. Default is true.
     * - [allowRevokeRefreshToken]: Whether revoking refresh token is allowed. Default is true.
     * - [tokenRevocationStorage]: Storage for revocation operations.
     */
    class BOM(
            /* common */
            val issuer: String = "astrea",
            val jsonEncoder: JsonEncoder,
            val httpClient: HttpClient,
            val scopeStrategy: ScopeStrategy = HierarchicalScopeStrategy,
            val base64Encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding(),
            val base64Decoder: Base64.Decoder = Base64.getUrlDecoder(),

            /* provider */
            val minStateEntropy: Int = 8,
            val minNonceEntropy: Int = 8,
            val clockSkewToleranceInSeconds: Int = 30,
            val resourceOwnerAuthenticator: ResourceOwnerAuthenticator? = null,

            /* authorize code */
            val authorizeCodeHmacKey: SecretKey = KeyGenerator.getInstance("AES").generateKey(),
            val authorizeCodeEntropy: Int = 32,
            val authorizeCodeStrategy: AuthorizeCodeStrategy? = null,
            val authorizeCodeStorage: AuthorizeCodeStorage,
            val authorizeCodeLifespanInSeconds: Long = 300,
            val authorizeRequestParamsToStore: List<String> = listOf(PARAM_CODE, PARAM_REDIRECT_URI),

            /* access token */
            val accessTokenJwk: RsaJsonWebKey = RsaJwkGenerator.generateJwk(2048),
            val accessTokenStrategy: AccessTokenStrategy? = null,
            val accessTokenStorage: AccessTokenStorage,
            val accessTokenLifespanInSeconds: Long = 3600,

            /* refresh token */
            val refreshTokenHmacKey: SecretKey = KeyGenerator.getInstance("AES").generateKey(),
            val refreshTokenEntropy: Int = 32,
            val refreshTokenStrategy: RefreshTokenStrategy? = null,
            val refreshTokenStorage: RefreshTokenStorage,

            /* id token */
            val idTokenJwk: RsaJsonWebKey = RsaJwkGenerator.generateJwk(2048),
            val idTokenStrategy: IdTokenStrategy? = null,
            val idTokenLifespanInSeconds: Long = 3600,
            val oidcRequestStorage: OpenIdConnectRequestStorage? = null,
            val allowOidcLoginPrompt: Boolean = true,
            val allowOidcNonePrompt: Boolean = true,
            val oidcAuthorizeRequestParamsToStore: List<String> = listOf(
                    PARAM_GRANT_TYPE,
                    PARAM_MAX_AGE,
                    PARAM_PROMPT,
                    PARAM_ACR_VALUE,
                    PARAM_ID_TOKEN_HINT,
                    PARAM_NONCE
            ),

            /* pkce */
            val allowPlainChallengeInPkce: Boolean = false,
            val allowS256ChallengeInPkce: Boolean = true,
            val pkceSessionStorage: PkceSessionStorage? = null,
            val miniPkceVerifierEntropy: Int = 32,

            /* client */
            val tokenEndpointUrl: String,
            val clientManager: ClientManager,
            val clientPasswordEncoder: PasswordEncoder = BCryptPasswordEncoder(hashComplexity = 10),
            val allowClientHttpBasicAuth: Boolean = false,
            val allowClientSecretPostAuth: Boolean = true,
            val allowClientPrivateKeyJwtAuth: Boolean = true,
            val allowClientNoneAuth: Boolean = true,

            /* introspection */
            val allowStatelessAccessTokenIntrospection: Boolean = true,
            val allowRefreshTokenIntrospection: Boolean = true,

            /* revocation */
            val allowRevokeAccessToken: Boolean = true,
            val allowRevokeRefreshToken: Boolean = true,
            val tokenRevocationStorage: TokenRevocationStorage
    )

    companion object {

        /**
         * Main entry to create an [Astrea] OAuth2 and Open ID Connect provider. By default, all features are turned on.
         * Users can selectively turn off features to customize. Turning features off will also ignore its related
         * configuration options from [bom]. For example, turning off PKCE via setting [enablePkce] to false will ignore
         * the PKCE section in [bom] as its no longer needed.
         *
         * @param bom                                   Bill of material for configurations.
         * @param enableOAuthAuthorizeFlow              Whether to enable OAuth authorize code flow.
         * @param enableOAuthImplicitFlow               Whether to enable OAuth implicit flow.
         * @param enableOAuthClientCredentialsFlow      Whether to enable OAuth client credentials flow.
         * @param enableOAuthRefreshFlow                Whether to enable OAuth refresh flow.
         * @param enableOAuthResourceOwnerFlow          Whether to enable OAuth resource owner password flow.
         * @param enablePkce                            Whether to enable PKCE enhancement for public clients.
         * @param enableOidcAuthorizeFlow               Whether to enable Open ID Connect authorize code flow.
         * @param enableOidcImplicitFlow                Whether to enable Open ID Connect implicit flow.
         * @param enableOidcHybridFlow                  Whether to enable Open ID Connect hybrid flow.
         * @param enableOidcRefreshFlow                 Whether to enable Open ID Connect refresh flow.
         * @param enableIntrospection                   Whether to enable token introspection.
         * @param enableRevocation                      Whether to enable token revocation.
         */
        fun compose(bom: BOM,
                    enableOAuthAuthorizeFlow: Boolean = true,
                    enableOAuthImplicitFlow: Boolean = true,
                    enableOAuthClientCredentialsFlow: Boolean = true,
                    enableOAuthRefreshFlow: Boolean = true,
                    enableOAuthResourceOwnerFlow: Boolean = true,
                    enablePkce: Boolean = true,
                    enableOidcAuthorizeFlow: Boolean = true,
                    enableOidcImplicitFlow: Boolean = true,
                    enableOidcHybridFlow: Boolean = true,
                    enableOidcRefreshFlow: Boolean = true,
                    enableIntrospection: Boolean = true,
                    enableRevocation: Boolean = true): OAuthProvider {

            val auth = DefaultAuthorizeProvider(
                    clientStore = bom.clientManager,
                    jsonEncoder = bom.jsonEncoder,
                    httpClient = bom.httpClient,
                    expectedAudience = bom.issuer,
                    scopeStrategy = bom.scopeStrategy,
                    minStateEntropy = bom.minStateEntropy,
                    clockSkewToleranceSecond = bom.clockSkewToleranceInSeconds,
                    outputDebugInErrorResponse = System.getenv("ASTREA_DEBUG")?.isNotBlank() ?: false,
                    authorizeHandler = mutableListOf<AuthorizeEndpointHandler>().also { h ->
                        if (enableOAuthAuthorizeFlow)
                            h.add(oauthAuthorizeCodeHandler(bom))
                        if (enableOAuthImplicitFlow)
                            h.add(oauthImplicitHandler(bom))
                        if (enablePkce)
                            h.add(oauthPkceHandler(bom))
                        if (enableOidcAuthorizeFlow)
                            h.add(oidcAuthorizeHandler(bom))
                        if (enableOidcImplicitFlow)
                            h.add(oidcImplicitHandler(bom))
                        if (enableOidcHybridFlow)
                            h.add(oidcHybridHandler(bom))
                    }.let { AuthorizeEndpointHandler.with(*it.toTypedArray()) }
            )

            val access = DefaultAccessProvider(
                    clientAuthenticator = clientAuthenticator(bom, enableIntrospection),
                    jsonEncoder = bom.jsonEncoder,
                    tokenEndpointHandler = mutableListOf<TokenEndpointHandler>().also { h ->
                        if (enableOAuthAuthorizeFlow)
                            h.add(oauthAuthorizeCodeHandler(bom))
                        if (enableOAuthClientCredentialsFlow)
                            h.add(oauthClientCredentialsHandler(bom))
                        if (enableOAuthRefreshFlow)
                            h.add(oauthRefreshHandler(bom))
                        if (enableOAuthResourceOwnerFlow)
                            h.add(oauthResourceOwnerPasswordHandler(bom))
                        if (enablePkce)
                            h.add(oauthPkceHandler(bom))
                        if (enableOidcAuthorizeFlow)
                            h.add(oidcAuthorizeHandler(bom))
                        if (enableOidcHybridFlow)
                            h.add(oidcHybridHandler(bom))
                        if (enableOidcRefreshFlow)
                            h.add(oidcRefreshHandler(bom))
                    }.let { TokenEndpointHandler.with(*it.toTypedArray()) },
                    outputDebugInErrorResponse = System.getenv("ASTREA_DEBUG")?.isNotBlank() ?: false
            )

            val introspect = if (!enableIntrospection) IntrospectionProvider.notSupported() else
                DefaultIntrospectionProvider(
                        clientAuthenticator = clientAuthenticator(bom, enableIntrospection || enableRevocation),
                        jsonEncoder = bom.jsonEncoder,
                        introspectHandler = introspectionHandler(bom)
                )

            val revocation = if (!enableRevocation) RevocationProvider.notSupported() else
                DefaultRevocationProvider(
                        clientAuthenticator = clientAuthenticator(bom, enableIntrospection || enableRevocation),
                        jsonEncoder = bom.jsonEncoder,
                        handler = revocationHandler(bom)
                )

            return Astrea(
                    authorizeProvider = auth,
                    accessProvider = access,
                    introspectionProvider = introspect,
                    revocationProvider = revocation
            )
        }

        private fun oauthAuthorizeCodeHandler(bom: BOM): OAuthAuthorizeCodeHandler = lazy {
            OAuthAuthorizeCodeHandler(
                    scopeStrategy = bom.scopeStrategy,
                    authorizeCodeStrategy = bom.authorizeCodeStrategy
                            ?: hmacAuthorizeCodeStrategy(bom),
                    accessTokenStrategy = bom.accessTokenStrategy
                            ?: jwtAccessTokenStrategy(bom),
                    refreshTokenStrategy = bom.refreshTokenStrategy
                            ?: hmacRefreshTokenStrategy(bom),
                    authorizeCodeStorage = bom.authorizeCodeStorage,
                    accessTokenStorage = bom.accessTokenStorage,
                    refreshTokenStorage = bom.refreshTokenStorage,
                    authorizeCodeLifespan = Duration.ofSeconds(bom.authorizeCodeLifespanInSeconds),
                    accessTokenLifespan = Duration.ofSeconds(bom.accessTokenLifespanInSeconds),
                    safeStorageParameters = bom.authorizeRequestParamsToStore
            )
        }.value

        private fun oauthImplicitHandler(bom: BOM): OAuthImplicitHandler = lazy {
            OAuthImplicitHandler(
                    scopeStrategy = bom.scopeStrategy,
                    accessTokenStrategy = bom.accessTokenStrategy ?: jwtAccessTokenStrategy(bom),
                    accessTokenLifespan = Duration.ofSeconds(bom.accessTokenLifespanInSeconds),
                    accessTokenStorage = bom.accessTokenStorage
            )
        }.value

        private fun oauthClientCredentialsHandler(bom: BOM): OAuthClientCredentialsHandler = lazy {
            OAuthClientCredentialsHandler(
                    scopeStrategy = bom.scopeStrategy,
                    accessTokenStorage = bom.accessTokenStorage,
                    accessTokenStrategy = bom.accessTokenStrategy ?: jwtAccessTokenStrategy(bom),
                    accessTokenLifespan = Duration.ofSeconds(bom.accessTokenLifespanInSeconds),
                    refreshTokenStorage = bom.refreshTokenStorage,
                    refreshTokenStrategy = bom.refreshTokenStrategy ?: hmacRefreshTokenStrategy(bom)
            )
        }.value

        private fun oauthRefreshHandler(bom: BOM): OAuthRefreshHandler = lazy {
            OAuthRefreshHandler(
                    accessTokenLifespan = Duration.ofSeconds(bom.accessTokenLifespanInSeconds),
                    accessTokenStrategy = bom.accessTokenStrategy ?: jwtAccessTokenStrategy(bom),
                    refreshTokenStrategy = bom.refreshTokenStrategy ?: hmacRefreshTokenStrategy(bom),
                    tokenRevocationStorage = bom.tokenRevocationStorage
            )
        }.value

        private fun oauthResourceOwnerPasswordHandler(bom: BOM): OAuthResourceOwnerHandler = lazy {
            requireNotNull(bom.resourceOwnerAuthenticator) {
                "when resource owner password flow is enabled, must provide resource owner authenticator."
            }
            OAuthResourceOwnerHandler(
                    scopeStrategy = bom.scopeStrategy,
                    accessTokenStrategy = bom.accessTokenStrategy ?: jwtAccessTokenStrategy(bom),
                    refreshTokenStrategy = bom.refreshTokenStrategy ?: hmacRefreshTokenStrategy(bom),
                    accessTokenLifespan = Duration.ofSeconds(bom.accessTokenLifespanInSeconds),
                    accessTokenStorage = bom.accessTokenStorage,
                    refreshTokenStorage = bom.refreshTokenStorage,
                    resourceOwnerAuthenticator = bom.resourceOwnerAuthenticator
            )
        }.value

        private fun oauthPkceHandler(bom: BOM): OAuthPkceHandler = lazy {
            requireNotNull(bom.pkceSessionStorage) {
                "when pkce is enabled, must provide pkce session storage"
            }
            OAuthPkceHandler(
                    authorizeCodeStrategy = bom.authorizeCodeStrategy ?: hmacAuthorizeCodeStrategy(bom),
                    allowPlainChallengeMethod = bom.allowPlainChallengeInPkce,
                    pkceSessionStorage = bom.pkceSessionStorage,
                    pkceValidator = mutableListOf<PkceValidator>().also { v ->
                        if (bom.allowPlainChallengeInPkce)
                            v.add(PlainPkceValidator)
                        else
                            v.add(DisallowPkceValidator(CodeChallengeMethod.Plain))

                        if (bom.allowS256ChallengeInPkce)
                            v.add(S256PkceValidator(
                                    minVerifierEntropy = bom.miniPkceVerifierEntropy,
                                    encoder = bom.base64Encoder,
                                    decoder = bom.base64Decoder
                            ))
                        else
                            v.add(DisallowPkceValidator(CodeChallengeMethod.S256))
                    }.let { PkceValidator.with(*it.toTypedArray()) }

            )
        }.value

        private fun oidcAuthorizeHandler(bom: BOM): OpenIdConnectAuthorizeCodeHandler = lazy {
            requireNotNull(bom.oidcRequestStorage) {
                "when oidc authorize flow is enabled, must provide oidc request storage."
            }
            OpenIdConnectAuthorizeCodeHandler(
                    authorizeCodeStrategy = bom.authorizeCodeStrategy ?: hmacAuthorizeCodeStrategy(bom),
                    openIdTokenStrategy = bom.idTokenStrategy ?: jwtIdTokenStrategy(bom),
                    openIdConnectRequestStorage = bom.oidcRequestStorage,
                    openIdConnectRequestValidator = oidcRequestValidator(bom),
                    openIdConnectSafeStorageParameters = bom.oidcAuthorizeRequestParamsToStore
            )
        }.value

        private fun oidcImplicitHandler(bom: BOM): OpenIdConnectImplicitHandler = lazy {
            OpenIdConnectImplicitHandler(
                    oauthImplicitHandler = oauthImplicitHandler(bom),
                    openIdConnectRequestValidator = oidcRequestValidator(bom),
                    scopeStrategy = bom.scopeStrategy,
                    openIdConnectTokenStrategy = bom.idTokenStrategy ?: jwtIdTokenStrategy(bom),
                    minimumNonceEntropy = bom.minNonceEntropy
            )
        }.value

        private fun oidcHybridHandler(bom: BOM): OpenIdConnectHybridHandler = lazy {
            requireNotNull(bom.oidcRequestStorage) {
                "when oidc hybrid flow is enabled, must provide oidc request storage."
            }
            OpenIdConnectHybridHandler(
                    openIdConnectAuthorizeCodeHandler = oidcAuthorizeHandler(bom),
                    openIdConnectTokenStrategy = bom.idTokenStrategy ?: jwtIdTokenStrategy(bom),
                    scopeStrategy = bom.scopeStrategy,
                    openIdConnectRequestValidator = oidcRequestValidator(bom),
                    openIdConnectSafeStorageParameters = bom.oidcAuthorizeRequestParamsToStore,
                    openIdConnectRequestStorage = bom.oidcRequestStorage,
                    authorizeCodeStrategy = bom.authorizeCodeStrategy ?: hmacAuthorizeCodeStrategy(bom),
                    authorizeCodeStorage = bom.authorizeCodeStorage,
                    oAuthImplicitHandler = oauthImplicitHandler(bom),
                    authorizeCodeSafeStorageParameters = bom.oidcAuthorizeRequestParamsToStore,
                    minimumNonceEntropy = bom.minNonceEntropy
            )
        }.value

        private fun oidcRefreshHandler(bom: BOM): OpenIdConnectRefreshHandler = lazy {
            OpenIdConnectRefreshHandler(
                    openIdConnectTokenStrategy = bom.idTokenStrategy ?: jwtIdTokenStrategy(bom)
            )
        }.value

        private fun introspectionHandler(bom: BOM): IntrospectEndpointHandler = lazy {
            mutableListOf<IntrospectEndpointHandler>().also { h ->
                if (bom.allowStatelessAccessTokenIntrospection)
                    h.add(AccessTokenJwtIntrospectHandler(
                            jwtRs256 = JwtRs256(bom.accessTokenJwk),
                            issuer = bom.issuer
                    ))
                else
                    h.add(AccessTokenStorageIntrospectHandler(
                            accessTokenStrategy = bom.accessTokenStrategy ?: jwtAccessTokenStrategy(bom),
                            accessTokenStorage = bom.accessTokenStorage
                    ))

                if (bom.allowRefreshTokenIntrospection)
                    h.add(RefreshTokenStorageIntrospectHandler(
                            refreshTokenStrategy = bom.refreshTokenStrategy ?: hmacRefreshTokenStrategy(bom),
                            refreshTokenStorage = bom.refreshTokenStorage
                    ))
            }.let { IntrospectEndpointHandler.with(*it.toTypedArray()) }
        }.value

        private fun revocationHandler(bom: BOM): RevocationEndpointHandler = lazy {
            mutableListOf<RevocationEndpointHandler>().also { h ->
                if (bom.allowRevokeAccessToken)
                    h.add(AccessTokenStorageRevocationHandler(
                            accessTokenStorage = bom.accessTokenStorage,
                            accessTokenStrategy = bom.accessTokenStrategy ?: jwtAccessTokenStrategy(bom),
                            tokenRevocationStorage = bom.tokenRevocationStorage
                    ))
                else
                    h.add(UnsupportedRevocationHandler(unsupported = listOf(TokenType.AccessToken)))

                if (bom.allowRevokeRefreshToken)
                    h.add(RefreshTokenStorageRevocationHandler(
                            refreshTokenStorage = bom.refreshTokenStorage,
                            refreshTokenStrategy = bom.refreshTokenStrategy ?: hmacRefreshTokenStrategy(bom),
                            tokenRevocationStorage = bom.tokenRevocationStorage
                    ))
                else
                    h.add(UnsupportedRevocationHandler(unsupported = listOf(TokenType.RefreshToken)))
            }.let { RevocationEndpointHandler.with(*it.toTypedArray()) }
        }.value

        private fun oidcRequestValidator(bom: BOM): OpenIdConnectRequestValidator = lazy {
            OpenIdConnectRequestValidator(
                    allowedPrompts = mutableListOf<Prompt>().also { p ->
                        if (bom.allowOidcLoginPrompt)
                            p.add(Prompt.Login)
                        if (bom.allowOidcNonePrompt)
                            p.add(Prompt.None)
                    },
                    jwtRs256 = JwtRs256(jwk = bom.idTokenJwk)
            )
        }.value

        private fun hmacAuthorizeCodeStrategy(bom: BOM): AuthorizeCodeStrategy = lazy {
            HmacAuthorizeCodeStrategy(
                    hmac = HmacSha256(
                            entropy = bom.authorizeCodeEntropy,
                            secretKey = bom.authorizeCodeHmacKey,
                            base64Decoder = bom.base64Decoder,
                            base64Encoder = bom.base64Encoder
                    )
            )
        }.value

        private fun jwtAccessTokenStrategy(bom: BOM): AccessTokenStrategy = lazy {
            JwtAccessTokenStrategy(
                    issuer = bom.issuer,
                    jwtRs256 = JwtRs256(
                            jwk = bom.accessTokenJwk
                    )
            )
        }.value

        private fun hmacRefreshTokenStrategy(bom: BOM): RefreshTokenStrategy = lazy {
            HmacRefreshTokenStrategy(
                    hmac = HmacSha256(
                            entropy = bom.refreshTokenEntropy,
                            secretKey = bom.refreshTokenHmacKey,
                            base64Encoder = bom.base64Encoder,
                            base64Decoder = bom.base64Decoder
                    )
            )
        }.value

        private fun jwtIdTokenStrategy(bom: BOM): IdTokenStrategy = lazy {
            JwtIdTokenStrategy(
                    jwtRs256 = JwtRs256(jwk = bom.idTokenJwk),
                    issuer = bom.issuer,
                    idTokenLifespan = Duration.ofSeconds(bom.idTokenLifespanInSeconds)
            )
        }.value

        private fun clientAuthenticator(bom: BOM, enableBearer: Boolean): ClientAuthenticator = lazy {
            mutableListOf<ClientAuthenticator>().also { v ->
                if (bom.allowClientHttpBasicAuth)
                    v.add(ClientSecretBasicAuthenticator(
                            clientManager = bom.clientManager,
                            passwordEncoder = bom.clientPasswordEncoder
                    ))
                if (bom.allowClientSecretPostAuth)
                    v.add(ClientSecretPostAuthenticator(
                            clientManager = bom.clientManager,
                            passwordEncoder = bom.clientPasswordEncoder
                    ))
                if (bom.allowClientPrivateKeyJwtAuth)
                    v.add(ClientPrivateKeyJwtAuthenticator(
                            clientManager = bom.clientManager,
                            tokenEndpointUrl = bom.tokenEndpointUrl
                    ))
                if (enableBearer)
                    v.add(ClientBearerPreIntrospectionAuthenticator(
                            accessTokenStorage = bom.accessTokenStorage,
                            accessTokenStrategy = bom.accessTokenStrategy ?: jwtAccessTokenStrategy(bom)
                    ))
                if (bom.allowClientNoneAuth)
                    v.add(ClientNoneAuthenticator(
                            clientManager = bom.clientManager
                    ))
            }.let { ClientAuthenticator.customChain(*it.toTypedArray()) }
        }.value
    }
}