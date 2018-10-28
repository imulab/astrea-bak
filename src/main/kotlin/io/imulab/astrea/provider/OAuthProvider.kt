package io.imulab.astrea.provider

/**
 * The main entry point of the SDK. This interface provides heavy lifting to most of the OAuth2 functions.
 *
 * The interface itself is a placeholder, it does not declare any methods. Instead, it is composed of a series of
 * sub-interfaces in order to clearly separate boundaries between functions. This is intended to promote readability
 * and maintainability of source codes.
 *
 * Implementations to this interface may directly compose implementations to its sub interfaces to provide entire
 * functions.
 *
 * @see AuthorizeProvider
 * @see AccessProvider
 * @see RevocationProvider
 * @see IntrospectionProvider
 */
interface OAuthProvider : AuthorizeProvider, AccessProvider, RevocationProvider, IntrospectionProvider