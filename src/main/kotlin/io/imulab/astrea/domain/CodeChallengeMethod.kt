package io.imulab.astrea.domain

import io.imulab.astrea.error.RequestParameterInvalidValueException

enum class CodeChallengeMethod(val specValue: String) {
    Plain("plain"),
    S256("S256");

    companion object {
        fun fromSpecValue(value: String, ignoreCase: Boolean = false): CodeChallengeMethod {
            val found = values().find {
                it.specValue.equals(value, ignoreCase)
            }
            return found ?: throw RequestParameterInvalidValueException.InvalidCodeChallengeMethod(value)
        }
    }
}