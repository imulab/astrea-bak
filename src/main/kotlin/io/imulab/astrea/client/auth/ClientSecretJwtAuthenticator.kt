package io.imulab.astrea.client.auth

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.spi.HttpRequestReader

/**
 * Implementation of [ClientAuthenticator] which is supported to handle 'client_secret_jwt'. However, we decided to
 * not support this due to security reasons.
 *
 * **IMPORTANT**
 * It is best to **not** compose this implementation in a chain of [ClientAuthenticator]. However, if must, it can still
 * be composed as long as it is loaded behind the [ClientPrivateKeyJwtAuthenticator]. Because both these authenticator
 * look for `client_assertion_type == urn:ietf:params:oauth:client-assertion-type:jwt-bearer` as the trigger condition,
 * putting this authenticator in front will always fail jwt-bearer authentication.
 */
class ClientSecretJwtAuthenticator : ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean {
        return reader.formValue("client_assertion_type") == jwtBearerClientAssertionType
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        throw UnsupportedOperationException("""
            We are not supporting this authentication mechanism because 'client_secret_jwt' requires using client
            secret as a shared HMAC SHA-256 key to sign the JWT. However, storing plain text secret or storing
            encrypted secret along with an encryption key is not safe and is therefore not support by this SDK.
        """.trimIndent())
    }

    companion object {
        const val jwtBearerClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    }
}