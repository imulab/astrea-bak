package io.imulab.astrea.crypt.hash

/**
 * Interface for hash function.
 */
interface Hasher {

    /**
     * Take the input [raw] byte array and produce its hash in byte array format.
     */
    fun hash(raw: ByteArray): ByteArray
}