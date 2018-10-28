package io.imulab.astrea.domain

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
            return found ?: throw IllegalArgumentException("$value does not match any response type.")
        }
    }
}