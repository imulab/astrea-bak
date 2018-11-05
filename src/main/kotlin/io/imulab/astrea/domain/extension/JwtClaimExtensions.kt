package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.*
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate

fun JwtClaims.setAccessTokenHash(hash: String) {
    this.setStringClaim(PARAM_ACCESS_TOKEN_HASH, hash)
}

fun JwtClaims.setAuthenticationContextClassReference(value: String) {
    this.setStringClaim(PARAM_ACR, value)
}

fun JwtClaims.getAuthenticationContextClassReference(): String {
    return this.getStringClaimValue(PARAM_ACR)
}

fun JwtClaims.setCodeHash(hash: String) {
    this.setStringClaim(PARAM_CODE_HASH, hash)
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