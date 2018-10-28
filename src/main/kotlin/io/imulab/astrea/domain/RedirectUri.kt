package io.imulab.astrea.domain

import io.imulab.astrea.error.MalformedRedirectUriException
import io.imulab.astrea.error.RedirectUriHasFragmentException
import io.imulab.astrea.error.UnmatchedRedirectUriException
import java.net.URI

typealias RedirectUri = String

/**
 * Match the supplied URI with registered URIs. According to the spec, if user does not
 * supply a redirect URI, it must be determined from the only registered redirect URI; if
 * user did supply a redirect URI, it must match with one of the registered redirect URI.
 *
 * @throws UnmatchedRedirectUriException when a match cannot be determined.
 */
fun RedirectUri?.determineRedirectUri(registered: List<String>): String {
    if (this.isNullOrBlank()) {
        if (registered.size == 1)
            return registered[0]
        else
            throw UnmatchedRedirectUriException()
    }

    if (registered.contains(this!!))
        return this
    else
        throw UnmatchedRedirectUriException()
}

/**
 * Check if the string represents a valid redirect URI. According to the spec:
 * - redirect uri must be properly formed. absolute-URI = scheme ":" hier-part [ "?" query ]
 * - redirect uri cannot have fragments
 */
fun RedirectUri.checkValidRedirectUri() {
    try {
        val uri = URI.create(this)
        if (!uri.isAbsolute)
            throw MalformedRedirectUriException(this)
        if (uri.rawFragment != null && uri.rawFragment.isNotEmpty())
            throw RedirectUriHasFragmentException(this)
    } catch (e: IllegalArgumentException) {
        throw MalformedRedirectUriException(this)
    }
}

/**
 * Check if the redirect uri is secure. We only allow localhost requests or https.
 */
fun RedirectUri.isSecureRedirectUri(): Boolean {
    return try {
        val uri = URI.create(this)
        (uri.scheme.toLowerCase() == "https") ||
                (uri.host.toLowerCase() == "localhost") ||
                (uri.host == "127.0.0.1")
    } catch (_: Exception) {
        false
    }
}