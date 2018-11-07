package io.imulab.astrea.domain

import io.imulab.astrea.error.RequestParameterInvalidValueException

enum class TokenType(val specValue: String) {
    AuthorizeCode("authorize_code"),
    Bearer("bearer"),
    AccessToken("access_token"),
    RefreshToken("refresh_token"),
    IdToken("id_token"),
    Unknown(""),
}

enum class TokenTypeHint(val specValue: String, val hinted: TokenType) {
    HintsAccessToken("access_token", TokenType.AccessToken),
    HintsRefreshToken("refresh_token", TokenType.RefreshToken);

    companion object {
        fun fromSpecValue(value: String, ignoreCase: Boolean = false): TokenTypeHint {
            val found = values().find {
                it.specValue.equals(value, ignoreCase)
            }
            return found ?: throw RequestParameterInvalidValueException.InvalidTokenTypeHint(value)
        }
    }
}