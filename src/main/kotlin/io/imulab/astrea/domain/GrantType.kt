package io.imulab.astrea.domain

enum class GrantType(val specValue: String) {
    AuthorizationCode("authorization_code"),
    Password("password"),
    ClientCredentials("client_credentials"),
    RefreshToken("refresh_token")
}