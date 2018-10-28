package io.imulab.astrea.provider.impl

import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.provider.AccessProvider
import io.imulab.astrea.spi.HttpRequestReader
import io.imulab.astrea.spi.HttpResponseWriter

class DefaultAccessProvider : AccessProvider {

    override fun newAccessRequest(reader: HttpRequestReader, session: Session): AccessRequest {
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