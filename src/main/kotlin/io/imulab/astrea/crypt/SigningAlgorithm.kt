package io.imulab.astrea.crypt

import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers

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