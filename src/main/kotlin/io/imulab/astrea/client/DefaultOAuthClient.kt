package io.imulab.astrea.client

import io.imulab.astrea.GrantType
import io.imulab.astrea.ResponseType

class DefaultOAuthClient(private val id: String,
                         private val secret: ByteArray,
                         private val redirectUris: List<String> = emptyList(),
                         private val grantTypes: List<GrantType> = emptyList(),
                         private val responseTypes: List<ResponseType> = emptyList(),
                         private val scopes: List<String> = emptyList(),
                         private val public: Boolean = false) : OAuthClient {

    override fun getId(): String = this.id

    override fun getHashedSecret(): ByteArray = this.secret

    override fun getRedirectUris(): List<String> = this.redirectUris

    override fun getGrantTypes(): Set<GrantType> = if (this.grantTypes.isEmpty())
        setOf(GrantType.AuthorizationCode) else this.grantTypes.toSet()

    override fun getResponseTypes(): Set<ResponseType> = if (this.responseTypes.isEmpty())
        setOf(ResponseType.Code) else this.responseTypes.toSet()

    override fun getScopes(): List<String> = this.scopes

    override fun isPublic(): Boolean = this.public
}