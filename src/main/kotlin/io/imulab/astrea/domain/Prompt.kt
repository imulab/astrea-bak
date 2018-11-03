package io.imulab.astrea.domain

enum class Prompt(val specValue: String) {
    None("none"),
    Login("long"),
    Consent("consent"),
    SelectAccount("select_account");

    companion object {
        fun fromSpecValue(value: String, ignoreCase: Boolean = false): Prompt {
            val found = values().find {
                it.specValue.equals(value, ignoreCase)
            }
            return found ?: throw IllegalArgumentException("$value does not match any prompt.")
        }
    }
}