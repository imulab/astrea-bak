package io.imulab.astrea.error

enum class TokenInvalidity(val text: String) {
    Expired("expired"),
    BadFormat("bad_format"),
    BadSignature("bad_signature")
}

class InvalidAuthorizeCodeException(invalidity: TokenInvalidity, reason: String? = null)
    : RuntimeException("""
        invalid authorize code (${invalidity.text}). ${reason?.trimEnd('.')?.plus(".") ?: ""}
    """.trimIndent())

class InvalidAccessTokenException(invalidity: TokenInvalidity, reason: String? = null)
    : RuntimeException("""
        invalid access token (${invalidity.text}). ${reason?.trimEnd('.')?.plus(".") ?: ""}
    """.trimIndent())

class InvalidRefreshTokenException(invalidity: TokenInvalidity, reason: String? = null)
    : RuntimeException("""
        invalid refresh token (${invalidity.text}). ${reason?.trimEnd('.')?.plus(".") ?: ""}
    """.trimIndent())