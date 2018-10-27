package io.imulab.astrea.access

class InvalidAccessTokenException(reason: String): RuntimeException("invalid access token: $reason")