package io.imulab.astrea.domain

enum class AuthMethod(val specValue: String) {
    ClientSecretJwt("client_secret_jwt"),
    ClientSecretBasic("client_secret_basic"),
    ClientSecretPost("client_secret_post"),
    PrivateKeyJwt("private_key_jwt"),
    None("none"),
}