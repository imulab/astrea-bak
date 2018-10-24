package io.imulab.astrea.client

/**
 * Persistence interface for [OAuthClient].
 */
interface ClientManager {

    /**
     * Get [OAuthClient] by its getId.
     */
    fun getClient(id: String): OAuthClient
}