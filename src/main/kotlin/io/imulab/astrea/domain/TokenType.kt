package io.imulab.astrea.domain

enum class TokenType(val specValue: String) {
    AuthorizeCode("authorize_code"),
    Bearer("bearer"),
    AccessToken("access_token"),
    RefreshToken("refresh_token"),
    IdToken("id_token"),
    Unknown(""),
}