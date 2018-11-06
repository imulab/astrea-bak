package io.imulab.astrea.domain

import io.imulab.astrea.error.RequestParameterInvalidValueException

enum class ResponseType(val specValue: String) {
    Code("code"),
    Token("token"),
    IdToken("id_token"),
    None("none");

    companion object {
        fun fromSpecValue(value: String, ignoreCase: Boolean = false): ResponseType {
            val found = values().find {
                it.specValue.equals(value, ignoreCase)
            }
            return found ?: throw RequestParameterInvalidValueException.InvalidResponseType(value)
        }
    }
}

fun Collection<ResponseType>.exactly(expected: ResponseType): Boolean =
        this.size == 1 && this.contains(expected)

