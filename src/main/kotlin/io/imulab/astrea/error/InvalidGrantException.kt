package io.imulab.astrea.error

/**
 * invalid_grant
 *
 * The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is
 * invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to
 * another client.
 */
open class InvalidGrantException(grant: String, reason: String)
    : OAuthException("invalid_grant", "Supplied grant '$grant' is invalid: $reason") {

    class ClientIdentityMismatch(grant: String) : InvalidGrantException(grant, "It was issued to another client.")

    class RedirectUriMismatch(grant: String) : InvalidGrantException(grant, "It was registered to a different redirect URI.")

    class NoOfflineAccess(grant: String) : InvalidGrantException(grant, "It does not have offline access.")

    class Expired(grant: String) : InvalidGrantException(grant, "It has expired.")

    class Inactive(grant: String) : InvalidGrantException(grant, "It was de-activated.")

    class NotFound(grant: String) : InvalidGrantException(grant, "It was not found in database.")

    class BadFormat(grant: String) : InvalidGrantException(grant, "It has invalid format.")

    class BadSignature(grant: String) : InvalidGrantException(grant, "Its signature does not match the grant.")
}