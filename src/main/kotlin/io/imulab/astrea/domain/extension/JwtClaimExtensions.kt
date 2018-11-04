package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.Scope
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate

fun JwtClaims.setAccessTokenHash(hash: String) {
    this.setStringClaim("at_hash", hash)
}

fun JwtClaims.setAuthenticationContextClassReference(value: String) {
    this.setStringClaim("acr", value)
}

fun JwtClaims.getAuthenticationContextClassReference(): String {
    return this.getStringClaimValue("acr")
}

fun JwtClaims.setCodeHash(hash: String) {
    this.setStringClaim("c_hash", hash)
}

fun JwtClaims.setAuthTime(time: NumericDate) {
    this.setNumericDateClaim("auth_time", time)
}

fun JwtClaims.getAuthTime(): NumericDate? {
    return this.getNumericDateClaimValue("auth_time")
}

fun JwtClaims.getRequestAtTime(): NumericDate? {
    return this.getNumericDateClaimValue("rat")
}

fun JwtClaims.setNonce(nonce: String) {
    this.setStringClaim("nonce", nonce)
}

fun JwtClaims.setScopes(scopes: List<Scope>) {
    this.setStringListClaim("scope", scopes)
}