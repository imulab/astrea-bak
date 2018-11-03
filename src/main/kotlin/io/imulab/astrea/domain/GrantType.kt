package io.imulab.astrea.domain

enum class GrantType(val specValue: String) {
    AuthorizationCode("authorization_code"),
    Implicit("implicit"),
    Password("password"),
    ClientCredentials("client_credentials"),
    RefreshToken("refresh_token");

    companion object {
        fun fromSpecValue(value: String, ignoreCase: Boolean = false): GrantType {
            val found = GrantType.values().find {
                it.specValue.equals(value, ignoreCase)
            }
            return found ?: throw IllegalArgumentException("$value does not match any grant type.")
        }
    }
}

fun Collection<GrantType>.exactly(expected: GrantType): Boolean =
        this.size == 1 && this.contains(expected)