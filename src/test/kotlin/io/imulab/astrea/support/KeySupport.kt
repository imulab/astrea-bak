package io.imulab.astrea.support

import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object KeySupport {

    private const val OPEN_JWK_ID = "default-jwk"

    val defaultJwk: RsaJsonWebKey by lazy { newJwk(OPEN_JWK_ID) }

    val defaultSecretKey: SecretKey by lazy { newSecretKey() }

    fun newJwk(id: String): RsaJsonWebKey {
        return RsaJwkGenerator.generateJwk(2048).also {
            it.keyId = id
            it.use = Use.SIGNATURE
        }
    }

    fun newSecretKey(): SecretKey {
        return KeyGenerator.getInstance("AES").generateKey()
    }
}