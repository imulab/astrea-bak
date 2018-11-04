package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.response.AccessResponse

fun AccessResponse.setRefreshToken(token: String) {
    this.setExtra("refresh_token", token)
}

fun AccessResponse.setIdToken(token: String) {
    this.setExtra("id_token", token)
}