package io.imulab.astrea.error

import io.imulab.astrea.domain.*

/**
 * invalid_request
 *
 * The request is missing a required parameter, includes an
 * unsupported parameter value (other than grant type),
 * repeats a parameter, includes multiple credentials,
 * utilizes more than one mechanism for authenticating the
 * client, or is otherwise malformed.
 */
sealed class InvalidRequestException(description: String? = null)
    : OAuthException("invalid_request", description) {

    override fun statusCode(): Int = 400
}

/**
 * Common base class for any [InvalidRequestException] that involves a request parameter name
 */
abstract class RequestParameterException(val parameterName: String, description: String? = null)
    : InvalidRequestException(description ?: "parameter '$parameterName' is invalid.")

/**
 * Thrown when request form is empty.
 */
class RequestFormIsEmptyException : InvalidRequestException("Request form is empty.")

/**
 * Thrown when response was not generated by any handlers.
 */
class RequestNotProcessedException : InvalidRequestException("Server cannot process this request.")

/**
 * A required parameter is missing or provided as blank.
 */
class RequestParameterMissingException(parameterName: String)
    : RequestParameterException("parameter '$parameterName' is missing or blank.")

/**
 * A parameter is included twice in the request.
 */
class RequestParameterRepeatedException(parameterName: String)
    : RequestParameterException("parameter '$parameterName' is provided more than once in the request.")

/**
 * A parameter value is invalid.
 */
open class RequestParameterInvalidValueException(parameterName: String, value: String, hint: String? = null)
    : RequestParameterException("parameter '$parameterName' has invalid value '$value'. ${hint ?: ""}".trim()) {

    class InvalidResponseType(value: String)
        : RequestParameterInvalidValueException(PARAM_RESPONSE_TYPE, value) {
        override fun isResponseTypeRelated(): Boolean = true
    }

    class InvalidGrantType(value: String)
        : RequestParameterInvalidValueException(PARAM_GRANT_TYPE, value)

    class InvalidPrompt(value: String)
        : RequestParameterInvalidValueException(PARAM_PROMPT, value)

    class InvalidCodeChallengeMethod(value: String)
        : RequestParameterInvalidValueException(PARAM_CODE_CHALLENGE_METHOD, value)

    class InvalidTokenTypeHint(value: String)
        : RequestParameterInvalidValueException(PARAM_TOKEN_TYPE_HINT, value)

    class StateInsufficientEntropy(value: String, minimumEntropy: Int)
        : RequestParameterInvalidValueException(PARAM_STATE, value, "State entropy is less than $minimumEntropy.")

    class NonceInsufficientEntropy(value: String, minimumEntropy: Int)
        : RequestParameterInvalidValueException(PARAM_NONCE, value, "Nonce entropy is less than $minimumEntropy.")

    class CodeVerifierInsufficientEntropy(minimumEntropy: Int)
        : RequestParameterInvalidValueException(PARAM_CODE_VERIFIER, "<redacted>", "Code verifier entropy is less than $minimumEntropy.")

    class InsecureRedirectUri(uri: String)
        : RequestParameterInvalidValueException(PARAM_REDIRECT_URI, uri, "Redirect URI '$uri' is not using HTTPS or 127.0.0.1 as host.")

    class MismatchedSubjectClaim(source: String)
        : RequestParameterInvalidValueException("sub", "n/a", "Detected contradicting value for 'sub' claim from $source.")

    class MultipleRedirectUriRegistered
        : RequestParameterInvalidValueException(PARAM_REDIRECT_URI, "n/a", "Unable to determine redirect URI. Client registered multiple but none was selected.")

    class RougeRedirectUri(uri: String)
        : RequestParameterInvalidValueException(PARAM_REDIRECT_URI, uri, "Request provided a redirect URI not registered by client.")

    class MalformedRedirectUri(uri: String, reason: String)
        : RequestParameterInvalidValueException(PARAM_REDIRECT_URI, uri, reason)

    class UnsupportedCodeChallengeMethod(disallow: CodeChallengeMethod)
        : RequestParameterInvalidValueException(PARAM_CODE_CHALLENGE_METHOD, disallow.specValue, "This code challenge method is not allowed by server.")

    class UnsupportedTokenType(tokenType: TokenType)
        : RequestParameterInvalidValueException(PARAM_TOKEN_TYPE, tokenType.specValue, "Operation on this token type is not supported by server.")
}

/**
 * A parameter (except scope) value is valid, but not supported.
 */
open class RequestParameterUnsupportedValueException(parameterName: String, value: String, hint: String? = null)
    : RequestParameterException("parameter '$parameterName' has valid value '$value', but is not supported for processing. ${hint
        ?: ""}".trim()) {

    /**
     * Registered response types of client does not contain the requested response type.
     */
    class ClientResponseType(value: String)
        : RequestParameterUnsupportedValueException(PARAM_RESPONSE_TYPE, value, "Client does not supported such response type.") {
        override fun isResponseTypeRelated(): Boolean = true
    }

    class ResponseTypeNotHandled(value: String)
        : RequestParameterUnsupportedValueException(PARAM_RESPONSE_TYPE, value, "Server does not supported such response type.") {
        override fun isResponseTypeRelated(): Boolean = true
    }
}
