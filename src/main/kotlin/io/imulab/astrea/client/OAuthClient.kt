package io.imulab.astrea.client

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType

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
}