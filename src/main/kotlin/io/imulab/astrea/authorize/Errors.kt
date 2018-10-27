package io.imulab.astrea.authorize

sealed class IllegalRedirectUriException(reason: String) :
        RuntimeException("Invalid redirect URI: $reason")

class UnmatchedRedirectUriException :
        IllegalRedirectUriException("effective redirect uri cannot be determined.")

class MalformedRedirectUriException(uriText: String) :
        IllegalRedirectUriException("malformed uri [$uriText].")

class RedirectUriHasFragmentException(uriText: String) :
        IllegalRedirectUriException("redirect uri [$uriText] cannot contain fragment.")

/**
 * Thrown when the provided authorize cannot be verified.
 */
class InvalidAuthorizeCodeException(code: String, reason: String):
        RuntimeException("authorize code \"$code\" is invalid: $reason")