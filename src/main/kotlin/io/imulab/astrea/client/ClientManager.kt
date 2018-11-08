package io.imulab.astrea.client

/**
 * Persistence interface for [OAuthClient].
 */
interface ClientManager {

    /**
     * Get [OAuthClient] by its getId.
     *
     * @throws [io.imulab.astrea.error.InvalidClientException.NotFound] when client is not found.
     */
    fun getClient(id: String): OAuthClient
}