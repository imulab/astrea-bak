package io.imulab.astrea.access

import io.imulab.astrea.HttpRequestReader
import io.imulab.astrea.HttpResponseWriter
import io.imulab.astrea.provider.AccessProvider
import io.imulab.astrea.oauth.OAuthSession

class DefaultAccessProvider : AccessProvider {

    override fun newAccessRequest(reader: HttpRequestReader, session: OAuthSession): AccessRequest {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun newAccessResponse(request: AccessRequest): AccessResponse {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encodeAccessResponse(writer: HttpResponseWriter, request: AccessRequest, response: AccessResponse) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun encodeAccessError(writer: HttpResponseWriter, request: AccessRequest, error: Throwable) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}