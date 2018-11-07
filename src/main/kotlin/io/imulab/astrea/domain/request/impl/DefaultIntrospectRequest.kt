package io.imulab.astrea.domain.request.impl

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.session.Session

class DefaultIntrospectRequest(
        private var token: String = "",
        private var tokenType: TokenType = TokenType.Unknown,
        private var session: Session,
        private var client: OAuthClient
) : IntrospectRequest {

    override fun getToken(): String = this.token

    override fun getTokenType(): TokenType = this.tokenType

    override fun getSession(): Session = this.session

    override fun getClient(): OAuthClient = this.client

    class Builder(
            var token: String = "",
            var tokenType: TokenType = TokenType.Unknown,
            var session: Session? = null,
            var client: OAuthClient? = null) {

        fun build(): IntrospectRequest {
            require(token.isNotEmpty())
            requireNotNull(session)
            requireNotNull(client)

            return DefaultIntrospectRequest(
                    token = token,
                    tokenType = tokenType,
                    client = client!!,
                    session = session!!
            )
        }
    }
}