package io.imulab.astrea.crypt.hash

import java.security.MessageDigest

class ShaHasher private constructor(private val messageDigest: MessageDigest) : Hasher {

    override fun hash(raw: ByteArray): ByteArray = messageDigest.digest(raw)

    companion object {

        /**
         * Produce a [Hasher] using SHA-256 algorithm.
         */
        fun usingSha256(): Hasher = ShaHasher(MessageDigest.getInstance("SHA-256"))

        /**
         * Produce a [Hasher] using SHA-512 algorithm.
         */
        fun usingSha512(): Hasher = ShaHasher(MessageDigest.getInstance("SHA-512"))
    }
}