package io.imulab.astrea.error

import io.imulab.astrea.domain.AuthMethod

/**
 * Thrown when:
 * Client authentication failed (e.g., unknown client, no client authentication included, or unsupported
 * authentication method).  The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate
 * which HTTP authentication schemes are supported.  If the client attempted to authenticate via the "Authorization"
 * request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and
 * include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.
 */
open class InvalidClientException(reason: String) : OAuthException("invalid_client", reason) {

    /**
     * Thrown when neither Json Web Keys nor Json Web Keys URI was registered.
     */
    class JwkNotFound : InvalidClientException("Client did not register either json web key or json web key URI.")

    /**
     * Thrown when user trying to use a public client for non-public oriented flows.
     */
    class PublicClient : InvalidClientException("Client is public.")

    /**
     * Thrown when an open id connect client was expected, but the client was not.
     */
    class NonOidcClient : InvalidClientException("Client cannot perform Open ID Connect functions.")

    /**
     * Thrown when client rejects the requested authentication method.
     */
    class IncapableOfAuthMethod(authMethod: AuthMethod)
        : InvalidClientException("Client is not capable of performing authentication method '${authMethod.specValue}'.")

    /**
     * Thrown when authentication fails.
     */
    class AuthenticationFailed(reason: String): InvalidClientException("Client failed authentication. $reason".trim())
}