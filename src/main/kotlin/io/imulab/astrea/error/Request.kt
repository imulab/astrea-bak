package io.imulab.astrea.error

sealed class InvalidRequestException(reason: String = "") :
        RuntimeException(reason.trimEnd('.').plus("."))

class HttpMethodMismatchException(expected: String, actual: String) :
        InvalidRequestException("HTTP method must be $expected, but it is $actual.")

class EmptyRequestException :
        InvalidRequestException("Request body is empty.")