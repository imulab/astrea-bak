package io.imulab.astrea.client

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.error.ClientGrantTypeException

/**
 * Represents a client in the context of OAuth protocol.
 */
interface OAuthClient {

    /**
     * Returns client getId.
     */
    fun getId(): String

    /**
     * Returns the hashed secret as byte array. Never return plain secret here.
     */
    fun getHashedSecret(): ByteArray

    /**
     * Returns all registered redirect URIs of the client.
     */
    fun getRedirectUris(): List<String>

    /**
     * Returns all registered grant types of the client.
     */
    fun getGrantTypes(): Set<GrantType>

    /**
     * Returns all registered response types of the client.
     */
    fun getResponseTypes(): Set<ResponseType>

    /**
     * Returns all getScopes allowed by the client. Scopes may be matched by strategies
     * other than string comparison.
     */
    fun getScopes(): List<String>

    /**
     * Returns true if the client is considered a public client.
     */
    fun isPublic(): Boolean

    /**
     * Asserts that this client has [expected] grant type. When this client does not
     * have the [expected] grant type, `[hard] == true` means it will throw exception;
     * `[hard] == false` means it will silently return result.
     */
    fun mustGrantType(expected: GrantType, hard: Boolean = true): Boolean {
        if (!this.getGrantTypes().contains(expected)) {
            if (hard)
                throw ClientGrantTypeException(this, expected)
            else
                return false
        }
        return true
    }
}