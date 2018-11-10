package io.imulab.astrea.support

import io.imulab.astrea.spi.user.ResourceOwnerAuthenticator
import io.imulab.astrea.spi.user.UserAuthenticationException
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

object UserSupport {

    val FIXED_PASSWORD = "s3cret"

    /**
     * Mocks an [ResourceOwnerAuthenticator] that takes a list of [invalidUsers] username as argument.
     * If any of these username (with password [FIXED_PASSWORD]) authenticates, the authenticator will throw [UserAuthenticationException].
     * Any other user authenticate will be fine.
     */
    fun authenticator(invalidUsers: List<String> = emptyList()): ResourceOwnerAuthenticator {
        val authenticator: ResourceOwnerAuthenticator = mock(ResourceOwnerAuthenticator::class.java)
        invalidUsers.forEach { username ->
            `when`(authenticator.authenticate(username, FIXED_PASSWORD))
                    .thenThrow(UserAuthenticationException::class.java)
        }
        return authenticator
    }
}