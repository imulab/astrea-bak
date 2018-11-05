package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.spi.http.delete
import io.imulab.astrea.spi.http.singleValue

fun OAuthRequest.getCode(): String {
    return this.getRequestForm().singleValue(PARAM_CODE)
}

fun OAuthRequest.getRedirectUri(): String {
    return this.getRequestForm().singleValue(PARAM_REDIRECT_URI)
}

fun OAuthRequest.getRefreshToken(): String {
    return this.getRequestForm().singleValue(PARAM_REFRESH_TOKEN)
}

fun OAuthRequest.getUsername(): String {
    return this.getRequestForm().singleValue(PARAM_USERNAME)
}

fun OAuthRequest.getPassword(): String {
    return this.getRequestForm().singleValue(PARAM_PASSWORD)
}

fun OAuthRequest.removePassword() {
    return this.getRequestForm().delete(PARAM_PASSWORD)
}

fun OAuthRequest.getNonce(): String {
    return this.getRequestForm().singleValue(PARAM_NONCE)
}

fun OAuthRequest.getPrompts(): List<Prompt> {
    return this.getRequestForm()
            .singleValue(PARAM_PROMPT)
            .split(SPACE)
            .filter { it.isNotEmpty() }
            .map { Prompt.fromSpecValue(it) }
            .toList()
}

fun OAuthRequest.getMaxAgeOrNull(): Long? {
    return this.getRequestForm().singleValue(PARAM_MAX_AGE).toLongOrNull()
}

fun OAuthRequest.getIdTokenHint(): String {
    return this.getRequestForm().singleValue(PARAM_ID_TOKEN_HINT)
}

fun OAuthRequest.getAuthenticationContextClassReferenceValue(): String {
    return this.getRequestForm().singleValue(PARAM_ACR_VALUE)
}

fun OAuthRequest.getGrantTypes(): List<GrantType> {
    return this.getRequestForm()
            .singleValue(PARAM_GRANT_TYPE)
            .split(SPACE)
            .filter { it.isNotEmpty() }
            .map { GrantType.fromSpecValue(it) }
            .toList()
}