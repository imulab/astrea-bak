package io.imulab.astrea.client

import io.imulab.astrea.oauth.AuthMethod
import io.imulab.astrea.oauth.SigningAlgorithm
import org.jose4j.jwk.JsonWebKeySet

/**
 * Represents a client in the context of Open ID Connect protocol.
 */
interface OpenIdConnectClient : OAuthClient {
    /**
     * Pre-registered request URIs.
     */
    fun getRequestUris(): List<String>

    /**
     * Returns the JWK set containing the public key.
     */
    fun getJsonWebKeys(): JsonWebKeySet?

    /**
     * Returns the public URI to the JWK set containing the public key.
     */
    fun getJsonKeyKeysUri(): String

    /**
     * JWS algorithm (JWA) required by this client. All request not signed with
     * this algorithm will be rejected.
     */
    fun getRequestObjectSigningAlgorithm(): SigningAlgorithm

    /**
     * Authentication method for the token endpoint.
     */
    fun getTokenEndpointAuthMethod(): AuthMethod

    /**
     * JWS algorithm that must be used for signing the JWT used to authenticate the
     * client at the token endpoint where the registered authentication method is
     * private_key_jwt or client_secret_jwt.
     */
    fun getTokenEndpointAuthSigningAlgorithm(): SigningAlgorithm
}