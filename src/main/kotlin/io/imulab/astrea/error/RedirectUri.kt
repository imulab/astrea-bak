package io.imulab.astrea.error

sealed class IllegalRedirectUriException(reason: String) :
        RuntimeException("Invalid redirect URI: $reason")

class UnmatchedRedirectUriException :
        IllegalRedirectUriException("effective redirect uri cannot be determined.")

class MalformedRedirectUriException(uriText: String) :
        IllegalRedirectUriException("malformed uri [$uriText].")

class RedirectUriHasFragmentException(uriText: String) :
        IllegalRedirectUriException("redirect uri [$uriText] cannot contain fragment.")

/**
 * Thrown when the presented redirect uri does not match the one restored from session storage. We raise exception
 * here to prevent any malicious redirect.
 */
class RedirectUriMismatchException(stored: String, presented: String) :
        RuntimeException("Redirect URI presented (${if (presented.isNotBlank()) presented else "<empty>"}) does not " +
                "match the one stored in session ($stored).")