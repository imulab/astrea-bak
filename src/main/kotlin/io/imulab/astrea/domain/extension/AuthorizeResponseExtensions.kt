package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.Scope
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.spi.http.singleValue

fun AuthorizeResponse.setAccessTokenAsFragment(token: String) {
    this.addFragment("access_token", token)
}

fun AuthorizeResponse.getAccessTokenFromFragment(): String {
    return this.getFragments().singleValue("access_token")
}

fun AuthorizeResponse.setExpiresInAsFragment(seconds: Long) {
    this.addFragment("expires_in", seconds.toString())
}

fun AuthorizeResponse.setTokenTypeAsFragment(tokenType: TokenType) {
    this.addFragment("token_type", tokenType.specValue)
}

fun AuthorizeResponse.setStateAsFragment(state: String) {
    this.addFragment("state", state)
}

fun AuthorizeResponse.getStateFromFragment(): String {
    return this.getFragments().singleValue("state")
}

fun AuthorizeResponse.setScopesAsFragment(scopes: List<Scope>) {
    this.addFragment("scope", scopes.joinToString(" "))
}

fun AuthorizeResponse.setCodeAsFragment(code: String) {
    this.addFragment("code", code)
}

fun AuthorizeResponse.setIdTokenAsFragment(token: String) {
    this.addFragment("id_token", token)
}

fun AuthorizeResponse.setCodeAsQuery(code: String) {
    this.addQuery("code", code)
}

fun AuthorizeResponse.setStateAsQuery(state: String) {
    this.addQuery("state", state)
}

fun AuthorizeResponse.setScopesAsQuery(scopes: List<Scope>) {
    this.addQuery("scope", scopes.joinToString(" "))
}