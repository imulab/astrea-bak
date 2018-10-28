package io.imulab.astrea.access

data class RefreshToken(val token: String,
                        val signature: String)