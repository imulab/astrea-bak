package io.imulab.astrea.token

data class AccessToken(val token: String,
                       val signature: String)