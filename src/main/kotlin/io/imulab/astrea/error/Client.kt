package io.imulab.astrea.error

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.GrantType

/**
 * Thrown when client does not have a necessary grant type in order to keep the processing going.
 */
class ClientGrantTypeException(client: OAuthClient, missingGrantType: GrantType) :
        RuntimeException("Client ${client.getId()} does not have required grant type '${missingGrantType.specValue}'.")

/**
 * Thrown when client identity presented in current request does not match the client identity restored from session storage.
 */
class ClientIdentityMismatchException(stored: OAuthClient, presented: OAuthClient) :
        RuntimeException("Client presented (client_id=${presented.getId()}) is not the client stored in session (client_id=${stored.getId()}).")

/**
 * Thrown when client authentication fails.
 */
class ClientAuthenticationException(reason: String = "") : RuntimeException("Client authentication failed. $reason")