package io.imulab.astrea.crypt

import org.mindrot.jbcrypt.BCrypt

class BCryptPasswordEncoder(private val hashComplexity: Int = 10): PasswordEncoder {

    override fun encode(plainPassword: CharSequence): String {
        return BCrypt.hashpw(plainPassword.toString(), BCrypt.gensalt(hashComplexity))
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String): Boolean {
        return BCrypt.checkpw(rawPassword.toString(), encodedPassword)
    }
}