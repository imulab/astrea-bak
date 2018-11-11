package io.imulab.astrea.error

fun NotSupported(reason: String): Nothing = throw UnsupportedOperationException("An operation is not supported: $reason")