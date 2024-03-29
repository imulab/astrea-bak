package io.imulab.astrea.crypt

import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.error.InvalidRequestObjectException
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwx.JsonWebStructure
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
import org.jose4j.keys.resolvers.VerificationKeyResolver
import java.security.Key

class ClientVerificationKeyResolver(private val client: OpenIdConnectClient) : VerificationKeyResolver {

    override fun resolveKey(jws: JsonWebSignature?, nestingContext: MutableList<JsonWebStructure>?): Key {
        if (jws?.keyIdHeaderValue?.isEmpty() == true)
            throw InvalidRequestObjectException("kid header in json web key is not set.")

        val kid = jws?.keyIdHeaderValue!!
        if (client.getJsonWebKeys() != null)
            return findPublicKey(client.getJsonWebKeys()!!, kid)

        return HttpsJwksVerificationKeyResolver(HttpsJwks(client.getJsonKeyKeysUri())).resolveKey(jws, nestingContext)
    }

    private fun findPublicKey(keySet: JsonWebKeySet, kid: String): Key {
        val use = Use.SIGNATURE
        val kty = client.getRequestObjectSigningAlgorithm().keyType
        return keySet.findJsonWebKey(kid, kty, use, null)?.key
                ?: throw InvalidRequestObjectException("public key not found for kid=$kid use=$use kty=$kty.")
    }
}