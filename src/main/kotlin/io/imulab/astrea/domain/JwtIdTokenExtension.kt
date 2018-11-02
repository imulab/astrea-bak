package io.imulab.astrea.domain

import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate

fun JwtClaims.getAuthTime(): NumericDate?
        = this.getNumericDateClaimValue("auth_time")

fun JwtClaims.getRequestAtTime(): NumericDate?
        = this.getNumericDateClaimValue("rat")

fun JwtClaims.getAuthenticationContextClassReference(): String =
        this.getStringClaimValue("acr") ?: ""

fun JwtClaims.setAuthenticationContextClassReference(value: String) {
    this.setStringClaim("acr", value)
}