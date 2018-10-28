package io.imulab.astrea.client

import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.AuthMethod
import org.jose4j.jwk.JsonWebKeySet

class DefaultOidcClient(private val oauth: OAuthClient,
                        private val requestUris: List<String> = emptyList<String>(),
                        private val jwkUri: String = "",
                        private val jwk: JsonWebKeySet?,
                        private val tokenEndpointAuth: AuthMethod = AuthMethod.None,
                        private val reqObjSignAlg: SigningAlgorithm = SigningAlgorithm.None) : OAuthClient by oauth, OpenIdConnectClient {

    override fun getRequestUris(): List<String> = this.requestUris

    override fun getJsonWebKeys(): JsonWebKeySet? = this.jwk

    override fun getJsonKeyKeysUri(): String = this.jwkUri

    override fun getRequestObjectSigningAlgorithm(): SigningAlgorithm = this.reqObjSignAlg

    override fun getTokenEndpointAuthMethod(): AuthMethod = this.tokenEndpointAuth

    override fun getTokenEndpointAuthSigningAlgorithm(): SigningAlgorithm = SigningAlgorithm.RS256
}