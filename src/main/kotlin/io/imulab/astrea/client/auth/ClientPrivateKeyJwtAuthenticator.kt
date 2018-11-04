package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.crypt.ClientVerificationKeyResolver
import io.imulab.astrea.domain.*
import io.imulab.astrea.error.ClientAuthenticationException
import io.imulab.astrea.spi.http.HttpRequestReader
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder

/**
 * Implementation of [ClientAuthenticator] to handle private_key_jwt authentication. This implementation requires
 * client_assertion_type parameter to be set to 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' in order to
 * be triggered.
 *
 * Client will be looked up according to the supplied 'client_id' parameter. If 'client_id' was not supplied, it will
 * do a skip-all-validation pass on the 'client_assertion' JWT token to lookup the issuer and use that as the client id.
 *
 * Client that uses this authentication method must have 'private_key_jwt' set as token endpoint authentication method.
 * In addition, the JWT supplied must have 'iss' and 'sub' set to the id of the client, 'aud' set to the value of
 * [tokenEndpointUrl], token id 'jti' set, and expiration 'exp' set. Other claims are ignored.
 */
class ClientPrivateKeyJwtAuthenticator(private val clientManager: ClientManager,
                                       private val tokenEndpointUrl: String) : ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean {
        return reader.formValue(PARAM_CLIENT_ASSERTION_TYPE) == JWT_BEARER_CLIENT_ASSERTION_TYPE
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        val clientAssertion = reader.formValue(PARAM_CLIENT_ASSERTION)
        if (clientAssertion.isEmpty())
            throw ClientAuthenticationException("client assertion is empty.")

        val clientId = resolveClientId(reader, clientAssertion)
        val client = clientManager.getClient(clientId) as? OpenIdConnectClient
                ?: throw ClientAuthenticationException("Client is not capable of performing Open ID Connect authentication.")
        if (client.getTokenEndpointAuthMethod() != AuthMethod.PrivateKeyJwt)
            throw ClientAuthenticationException("Client is not capable of performing Open ID Connect private_key_jwt authentication.")

        try {
            JwtConsumerBuilder()
                    .setSkipVerificationKeyResolutionOnNone()
                    .setVerificationKeyResolver(ClientVerificationKeyResolver(client))
                    .setAllowedClockSkewInSeconds(30)
                    .setExpectedIssuer(true, clientId)
                    .setExpectedSubject(clientId)
                    .setExpectedAudience(true, tokenEndpointUrl)
                    .setRequireJwtId()
                    .setRequireExpirationTime()
                    .build()
                    .process(clientAssertion)
        } catch (e: InvalidJwtException) {
            throw ClientAuthenticationException("invalid client assertion (${e.message}).")
        }

        return client
    }

    /**
     * Resolves the client_id. The 'client_id' parameter specified in the request form takes precedence. If it is not
     * found, we will run a no-verification pass on the assertion and extract the 'iss' value.
     */
    private fun resolveClientId(reader: HttpRequestReader, clientAssertion: String): String {
        val clientId = reader.formValue(PARAM_CLIENT_ID)
        if (clientId.isNotBlank())
            return clientId

        val jwtClaims = JwtConsumerBuilder()
                .setDisableRequireSignature()
                .setSkipAllDefaultValidators()
                .setSkipSignatureVerification()
                .build()
                .processToClaims(clientAssertion)
        return jwtClaims.issuer
    }
}