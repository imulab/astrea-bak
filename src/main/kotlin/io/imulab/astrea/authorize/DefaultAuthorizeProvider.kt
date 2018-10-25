package io.imulab.astrea.authorize

import io.imulab.astrea.AuthorizeProvider
import io.imulab.astrea.HttpRequestReader
import io.imulab.astrea.HttpResponseWriter
import io.imulab.astrea.OAuthSession

class DefaultAuthorizeProvider: AuthorizeProvider {


    override fun newAuthorizeRequest(reader: HttpRequestReader): AuthorizeRequest {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun newAuthorizeResponse(request: AuthorizeRequest, session: OAuthSession): AuthorizeResponse {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encodeAuthorizeResponse(writer: HttpResponseWriter, request: AuthorizeRequest, response: AuthorizeResponse) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encodeAuthorizeError(writer: HttpResponseWriter, request: AuthorizeRequest, error: Throwable) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}