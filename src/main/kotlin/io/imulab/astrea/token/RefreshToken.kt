package io.imulab.astrea.token

data class RefreshToken(val token: String,
                        val signature: String)