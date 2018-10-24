package io.imulab.astrea

enum class GrantType {
    AuthorizationCode
}

enum class ResponseType {
    Code
}

enum class TokenType(val specValue: String) {
    AuthorizeCode("authorize_code"),
    AccessToken("access_token"),
    RefreshToken("refresh_token"),
    IdToken("id_token"),
    Unknown(""),
}