package io.imulab.astrea.access

data class AccessToken(val token: String,
                       val signature: String)