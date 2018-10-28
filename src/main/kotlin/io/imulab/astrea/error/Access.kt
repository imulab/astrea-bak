package io.imulab.astrea.error

class InvalidAccessTokenException(reason: String) : RuntimeException("invalid access token: $reason")

