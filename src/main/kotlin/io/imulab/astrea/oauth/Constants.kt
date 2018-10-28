package io.imulab.astrea.oauth

import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers

enum class GrantType(val specValue: String) {
    AuthorizationCode("authorization_code"),
    Password("password"),
    ClientCredentials("client_credentials"),
    RefreshToken("refresh_token")
}

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

enum class TokenType(val specValue: String) {
    AuthorizeCode("authorize_code"),
    Bearer("bearer"),
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

enum class SigningAlgorithm(val specValue: String, val keyType: String) {
    RS256(AlgorithmIdentifiers.RSA_USING_SHA256, RsaJsonWebKey.KEY_TYPE) {
        override fun toJwsAlgorithmConstraints(): AlgorithmConstraints =
                AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256)
    },
    None(AlgorithmIdentifiers.NONE, "none") {
        override fun toJwsAlgorithmConstraints(): AlgorithmConstraints =
                AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.NONE)
    };

    abstract fun toJwsAlgorithmConstraints(): AlgorithmConstraints
}