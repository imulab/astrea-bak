package io.imulab.astrea.handler.validator

import io.imulab.astrea.crypt.hash.Hasher
import io.imulab.astrea.crypt.hash.ShaHasher
import io.imulab.astrea.domain.CodeChallengeMethod
import io.imulab.astrea.error.CodeChallengeException
import io.imulab.astrea.error.RequestNotProcessedException
import io.imulab.astrea.error.RequestParameterInvalidValueException
import java.util.*

/**
 * Validates a Pkce verifier against a Pkce challenge
 */
interface PkceValidator {

    companion object {
        fun with(vararg validator: PkceValidator): PkceValidator =
                DelegatingPkceValidator(validator.toList())
    }

    /**
     * Returns true if this validator supports [method]
     */
    fun supports(method: CodeChallengeMethod): Boolean

    /**
     * Validates the given [verifier] against the [challenge].
     *
     * @throws [io.imulab.astrea.error.CodeChallengeException] when validation fails.
     */
    fun validate(method: CodeChallengeMethod, challenge: String, verifier: String)

    private class DelegatingPkceValidator(private val delegates: List<PkceValidator>) : PkceValidator {

        override fun supports(method: CodeChallengeMethod): Boolean = delegates.any { it.supports(method) }

        override fun validate(method: CodeChallengeMethod, challenge: String, verifier: String) {
            val validators = delegates.filter { it.supports(method) }
            if (validators.isEmpty())
                throw RequestNotProcessedException()
            validators.forEach { it.validate(method, challenge, verifier) }
        }
    }
}

/**
 * Implementation of [PkceValidator] which rejects certain [CodeChallengeMethod] because the server does not support
 * it
 */
class DisallowPkceValidator(private val disallow: CodeChallengeMethod) : PkceValidator {

    override fun supports(method: CodeChallengeMethod): Boolean = method == disallow

    override fun validate(method: CodeChallengeMethod, challenge: String, verifier: String) {
        if (method == disallow)
            throw RequestParameterInvalidValueException.UnsupportedCodeChallengeMethod(disallow)
    }
}

object PlainPkceValidator : PkceValidator {
    override fun supports(method: CodeChallengeMethod): Boolean = method == CodeChallengeMethod.Plain

    override fun validate(method: CodeChallengeMethod, challenge: String, verifier: String) {
        assert(method == CodeChallengeMethod.Plain) { "this validator accept ${CodeChallengeMethod.Plain} method." }

        if (verifier != challenge)
            throw CodeChallengeException()
    }
}

class S256PkceValidator(private val minVerifierEntropy: Int = 32,
                        private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding(),
                        private val decoder: Base64.Decoder = Base64.getUrlDecoder()) : PkceValidator {

    private val hasher: Hasher = ShaHasher.usingSha256()

    override fun supports(method: CodeChallengeMethod): Boolean = method == CodeChallengeMethod.S256

    override fun validate(method: CodeChallengeMethod, challenge: String, verifier: String) {
        assert(method == CodeChallengeMethod.S256) { "this validator accept ${CodeChallengeMethod.S256} method." }

        val decodedVerifier = decoder.decode(verifier)
        if (decodedVerifier.size < minVerifierEntropy)
            throw RequestParameterInvalidValueException.CodeVerifierInsufficientEntropy(minVerifierEntropy)

        val hashedVerifier = hasher.hash(decodedVerifier).let { encoder.encodeToString(it) }
        if (hashedVerifier != challenge)
            throw CodeChallengeException()
    }
}