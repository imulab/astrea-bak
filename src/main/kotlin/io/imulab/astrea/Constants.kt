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

enum class AuthMethod(val specValue: String) {
    ClientSecretJwt("client_secret_jwt"),
    ClientSecretBasic("client_secret_basic"),
    ClientSecretPost("client_secret_post"),
    PrivateKeyJwt("private_key_jwt"),
    None("none"),
}

enum class SigningAlgorithm {
    RS256,
    None,
}