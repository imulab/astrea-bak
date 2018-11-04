package io.imulab.astrea.token.strategy

import io.imulab.astrea.crypt.hash.Hasher
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.IdToken
import java.util.*

/**
 * Strategy for Open ID Connect id_token.
 */
interface IdTokenStrategy {

    /**
     * Returns the [Hasher] which uses the same hash algorithm as generating the id token.
     */
    fun getHasher(): Hasher

    /**
     * Generate a new Open ID Connect id_token.
     */
    fun generateIdToken(request: OAuthRequest): IdToken

    /**
     * Take the octet form of the [value], calculate its hash using [getHasher], and then
     * base64 encode the left most half of the hash result. Useful in calculating at_hash and c_hash values
     */
    fun leftMostHash(value: String, encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()): String {
        val hashed = getHasher().hash(value.toByteArray())
        return encoder.encodeToString(hashed.copyOfRange(0, hashed.size/2))
    }
}