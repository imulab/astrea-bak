package io.imulab.astrea.support

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.SCOPE_OFFLINE
import io.imulab.astrea.domain.Scope
import io.imulab.astrea.domain.extension.setScopes
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.request.impl.DefaultAccessRequest
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.spi.http.UrlValues
import org.jose4j.jwt.JwtClaims

object RequestSupport {

    fun newAuthorizeRequest(
            client: OAuthClient = ClientSupport.foo(),
            responseTypes: Set<ResponseType> = setOf(ResponseType.Code),
            redirectUri: String = ClientSupport.OPEN_CALLBACK,
            scopes: Set<Scope> = setOf("foo", "bar", SCOPE_OFFLINE),
            grantedScopes: Set<Scope> = setOf("foo", SCOPE_OFFLINE),
            state: String = "1234567890",
            session: Session? = null,
            jwtClaimModifier: (JwtClaims) -> Unit = {}
    ): AuthorizeRequest {
        return DefaultAuthorizeRequest.Builder().also { b ->
            b.client = client
            b.responseTypes.addAll(responseTypes)
            b.redirectUri = redirectUri
            b.scopes.addAll(scopes)
            b.grantedScopes.addAll(grantedScopes)
            b.state = state
            b.session = session ?: DefaultJwtSession.Builder().also {
                it.getClaims().setScopes(listOf("foo", SCOPE_OFFLINE))
                it.getClaims().also(jwtClaimModifier)
            }.build()
        }.build() as AuthorizeRequest
    }

    fun newAccessRequest(form: UrlValues = emptyMap(),
                         grantTypes: Set<GrantType> = setOf(GrantType.AuthorizationCode),
                         session: Session? = null,
                         client: OAuthClient = ClientSupport.foo()): AccessRequest {
        return DefaultAccessRequest.Builder().also {
            it.setForm(form)
            it.addGrantType(grantTypes.toList())
            it.session = session ?: DefaultSession()
            it.client = client
        }.build() as AccessRequest
    }
}