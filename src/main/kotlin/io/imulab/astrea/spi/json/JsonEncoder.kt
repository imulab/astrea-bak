package io.imulab.astrea.spi.json

import java.nio.charset.StandardCharsets

/**
 * Service provider interface to abstract the capability to encode JSON so this SDK does not have to choose
 * a JSON library for users.
 */
interface JsonEncoder {

    /**
     * Encode the given object [any] to JSON format, optionally select whether to encode prettily.
     * Returns byte form of the result encoding.
     */
    fun encode(any: Any, pretty: Boolean = false): ByteArray

    /**
     * Encode the given object [any] to JSON format, optionally select whether to encode prettily.
     * Returns string form of the result encoding.
     */
    fun encodeToString(any: Any, pretty: Boolean = false): String =
            encode(any, pretty).toString(StandardCharsets.UTF_8)
}