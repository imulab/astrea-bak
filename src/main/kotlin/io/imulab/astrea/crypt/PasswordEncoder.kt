package io.imulab.astrea.crypt

/**
 * Logic to compare and convert between a raw/plain-text password and an encoded password.
 */
interface PasswordEncoder {

    /**
     * Encodes the [plainPassword].
     */
    fun encode(plainPassword: CharSequence): String

    /**
     * Returns true if the [rawPassword] is indeed the plain text form of [encodedPassword]. Otherwise, returns false.
     */
    fun matches(rawPassword: CharSequence, encodedPassword: String): Boolean
}