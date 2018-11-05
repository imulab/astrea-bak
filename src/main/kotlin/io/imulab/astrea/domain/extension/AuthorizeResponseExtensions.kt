package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.spi.http.singleValue

fun AuthorizeResponse.setAccessTokenAsFragment(token: String) {
    this.addFragment(PARAM_ACCESS_TOKEN, token)
}

fun AuthorizeResponse.getAccessTokenFromFragment(): String {
    return this.getFragments().singleValue(PARAM_ACCESS_TOKEN)
}

fun AuthorizeResponse.setExpiresInAsFragment(seconds: Long) {
    this.addFragment(PARAM_EXPIRES_IN, seconds.toString())
}

fun AuthorizeResponse.setTokenTypeAsFragment(tokenType: TokenType) {
    this.addFragment(PARAM_TOKEN_TYPE, tokenType.specValue)
}

fun AuthorizeResponse.setStateAsFragment(state: String) {
    this.addFragment(PARAM_STATE, state)
}

fun AuthorizeResponse.getStateFromFragment(): String {
    return this.getFragments().singleValue(PARAM_STATE)
}

fun AuthorizeResponse.setScopesAsFragment(scopes: List<Scope>) {
    this.addFragment(PARAM_SCOPE, scopes.joinToString(SPACE))
}

fun AuthorizeResponse.setCodeAsFragment(code: String) {
    this.addFragment(PARAM_CODE, code)
}

fun AuthorizeResponse.setIdTokenAsFragment(token: String) {
    this.addFragment(PARAM_ID_TOKEN, token)
}

fun AuthorizeResponse.getIdTokenFromFragment(): String {
    return this.getFragments().singleValue(PARAM_ID_TOKEN)
}

fun AuthorizeResponse.setCodeAsQuery(code: String) {
    this.addQuery(PARAM_CODE, code)
}

fun AuthorizeResponse.setStateAsQuery(state: String) {
    this.addQuery(PARAM_STATE, state)
}

fun AuthorizeResponse.setScopesAsQuery(scopes: List<Scope>) {
    this.addQuery(PARAM_SCOPE, scopes.joinToString(SPACE))
}