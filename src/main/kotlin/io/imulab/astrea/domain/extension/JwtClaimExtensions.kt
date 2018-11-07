package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.*
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate

fun JwtClaims.optionalStringClaim(name: String, default: String = ""): String {
    return if (this.hasClaim(name))
        this.getStringClaimValue(name)
    else default
}

fun JwtClaims.setAccessTokenHash(hash: String) {
    this.setStringClaim(PARAM_ACCESS_TOKEN_HASH, hash)
}

fun JwtClaims.getAccessTokenHash(): String {
    return this.optionalStringClaim(PARAM_ACCESS_TOKEN_HASH)
}

fun JwtClaims.setAuthenticationContextClassReference(value: String) {
    this.setStringClaim(PARAM_ACR, value)
}

fun JwtClaims.getAuthenticationContextClassReference(): String {
    return this.optionalStringClaim(PARAM_ACR)
}

fun JwtClaims.setCodeHash(hash: String) {
    this.setStringClaim(PARAM_CODE_HASH, hash)
}

fun JwtClaims.getCodeHash(): String {
    return this.optionalStringClaim(PARAM_CODE_HASH)
}

fun JwtClaims.setAuthTime(time: NumericDate) {
    this.setNumericDateClaim(PARAM_AUTH_TIME, time)
}

fun JwtClaims.getAuthTime(): NumericDate? {
    return this.getNumericDateClaimValue(PARAM_AUTH_TIME)
}

fun JwtClaims.getRequestAtTime(): NumericDate? {
    return this.getNumericDateClaimValue(PARAM_REQUEST_AT_TIME)
}

fun JwtClaims.setRequestAtTime(time: NumericDate) {
    this.setNumericDateClaim(PARAM_REQUEST_AT_TIME, time)
}

fun JwtClaims.setNonce(nonce: String) {
    this.setStringClaim(PARAM_NONCE, nonce)
}

fun JwtClaims.setScopes(scopes: List<Scope>) {
    this.setStringListClaim(PARAM_SCOPE, scopes)
}

fun JwtClaims.getScopes(): List<Scope> {
    return if (this.hasClaim(PARAM_SCOPE))
        this.getStringListClaimValue(PARAM_SCOPE)
    else emptyList()
}