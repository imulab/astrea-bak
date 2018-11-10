package io.imulab.astrea.handler

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.PARAM_GRANT_TYPE
import io.imulab.astrea.domain.SCOPE_OPENID
import io.imulab.astrea.domain.extension.getIdToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.handler.flow.OpenIdConnectRefreshHandler
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OpenIdConnectRefreshHandlerSpec : Spek({

    val handler = OpenIdConnectRefreshHandler(TokenSupport.IdToken.defaultStraegy)

    describe("correct flow") {

        var request: AccessRequest? = null
        var response: AccessResponse? = null

        it("""
            should handle access request
        """.trimIndent()) {
            request = RequestSupport.newAccessRequest(
                    grantTypes = setOf(GrantType.RefreshToken),
                    grantedScopes = setOf(SCOPE_OPENID),
                    client = ClientSupport.bar(),
                    session = DefaultOidcSession.Builder().also { b ->
                        b.getClaims().run { subject = "imulab" }
                    }.build(),
                    form = mapOf(
                            PARAM_GRANT_TYPE to listOf(GrantType.AuthorizationCode.specValue)
                    )
            )

            assertThat(handler.supports(request!!)).isTrue()
            assertThatCode {
                handler.handleAccessRequest(request!!)
            }.doesNotThrowAnyException()
        }

        it("""
            should populate access response
        """.trimIndent()) {
            response = DefaultAccessResponse().also {
                it.setAccessToken(TokenSupport.AccessToken.new().token)
            }

            assertThatCode {
                handler.populateAccessResponse(request!!, response!!)
            }.doesNotThrowAnyException()
        }

        it("""
            should have issued new id_token
        """.trimIndent()) {
            assertThat(response)
                    .isNotNull
                    .extracting { it!!.getIdToken() }
                    .asString()
                    .isNotEmpty()
        }
    }
})