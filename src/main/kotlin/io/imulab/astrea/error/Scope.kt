package io.imulab.astrea.error

import io.imulab.astrea.domain.Scope

/**
 * Thrown when a scope cannot be granted.
 */
class ScopeRejectedException(rejected: Scope) :
        RuntimeException("Scope '$rejected' cannot be accepted.")

/**
 * Thrown when an operation requires a scope to continue, but it was not granted.
 */
class ScopeNotGrantedException(required: Scope) :
        RuntimeException("Scope '$required' was not granted.")