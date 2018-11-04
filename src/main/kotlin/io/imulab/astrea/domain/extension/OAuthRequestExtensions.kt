package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.Prompt
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.spi.http.delete
import io.imulab.astrea.spi.http.singleValue

fun OAuthRequest.getCode(): String {
    return this.getRequestForm().singleValue("code")
}

fun OAuthRequest.getRedirectUri(): String {
    return this.getRequestForm().singleValue("redirect_uri")
}

fun OAuthRequest.getRefreshToken(): String {
    return this.getRequestForm().singleValue("refresh_token")
}

fun OAuthRequest.getUsername(): String {
    return this.getRequestForm().singleValue("username")
}

fun OAuthRequest.getPassword(): String {
    return this.getRequestForm().singleValue("password")
}

fun OAuthRequest.removePassword() {
    return this.getRequestForm().delete("password")
}

fun OAuthRequest.getNonce(): String {
    return this.getRequestForm().singleValue("nonce")
}

fun OAuthRequest.getPrompts(): List<Prompt> {
    return this.getRequestForm()
            .singleValue("prompt")
            .split(" ")
            .map { Prompt.fromSpecValue(it) }
            .toList()
}

fun OAuthRequest.getMaxAgeOrNull(): Long? {
    return this.getRequestForm().singleValue("max_age").toLongOrNull()
}

fun OAuthRequest.getIdTokenHint(): String {
    return this.getRequestForm().singleValue("id_token_hint")
}

fun OAuthRequest.getAuthenticationContextClassReferenceValue(): String {
    return this.getRequestForm().singleValue("acr_value")
}

fun OAuthRequest.getGrantTypes(): List<GrantType> {
    return this.getRequestForm()
            .singleValue("grant_type")
            .split(" ")
            .map { GrantType.fromSpecValue(it) }
            .toList()
}