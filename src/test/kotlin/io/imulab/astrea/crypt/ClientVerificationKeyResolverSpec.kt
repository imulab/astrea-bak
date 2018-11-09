package io.imulab.astrea.crypt

import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.error.InvalidRequestObjectException
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.KeySupport
import io.imulab.astrea.support.TokenSupport
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.nio.charset.StandardCharsets

object ClientVerificationKeyResolverSpec : Spek({

    val keyFoo = KeySupport.newJwk("key_foo")
    val resolver = ClientVerificationKeyResolver(
            client = ClientSupport.bar(jwks = listOf(keyFoo)) as OpenIdConnectClient)

    describe("Resolver should resolve correct key") {
        it("""
            when jws specifies key id in collection
        """.trimIndent()) {
            assertThat(
                    resolver.resolveKey(jws = TokenSupport.customJws(
                            keyId = keyFoo.keyId
                    ), nestingContext = null))
                    .isNotNull
                    .extracting { key -> key.encoded.toString(StandardCharsets.UTF_8) }
                    .isEqualTo(keyFoo.getRsaPublicKey().encoded.toString(StandardCharsets.UTF_8))
        }
    }

    describe("Resolver should not resolve any key") {
        it("""
            when jws specifies key id out of collection
        """.trimIndent()) {
            assertThatThrownBy {
                resolver.resolveKey(jws = TokenSupport.customJws(keyId = "bar"), nestingContext = null)
            }.isInstanceOf(InvalidRequestObjectException::class.java)
        }
    }
})