package io.imulab.astrea.error

import io.imulab.astrea.domain.GrantType

/**
 * unauthorized_client
 *
 * The authenticated client is not authorized to use this authorization grant type.
 */
class UnauthorizedClientException(grantType: GrantType)
    : OAuthException("unauthorized_client", "The client is not authorized to use grant type '${grantType.specValue}'.")