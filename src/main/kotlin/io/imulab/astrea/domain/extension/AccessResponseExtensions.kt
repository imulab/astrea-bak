package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.PARAM_ID_TOKEN
import io.imulab.astrea.domain.PARAM_REFRESH_TOKEN
import io.imulab.astrea.domain.response.AccessResponse

fun AccessResponse.setRefreshToken(token: String) {
    this.setExtra(PARAM_REFRESH_TOKEN, token)
}

fun AccessResponse.getRefreshToken(): String {
    return this.getExtra(PARAM_REFRESH_TOKEN) as? String ?: ""
}

fun AccessResponse.setIdToken(token: String) {
    this.setExtra(PARAM_ID_TOKEN, token)
}

fun AccessResponse.getIdToken(): String {
    return this.getExtra(PARAM_ID_TOKEN) as? String ?: ""
}