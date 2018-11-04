package io.imulab.astrea.domain

import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate

fun JwtClaims.setAccessTokenHash(hash: String) {
    this.setStringClaim("at_hash", hash)
}

fun JwtClaims.setAuthenticationContextClassReference(value: String) {
    this.setStringClaim("acr", value)
}

fun JwtClaims.setCodeHash(hash: String) {
    this.setStringClaim("c_hash", hash)
}

fun JwtClaims.setAuthTime(time: NumericDate) {
    this.setNumericDateClaim("auth_time", time)
}

fun JwtClaims.setNonce(nonce: String) {
    this.setStringClaim("nonce", nonce)
}