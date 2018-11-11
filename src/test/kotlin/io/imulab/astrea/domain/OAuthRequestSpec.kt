package io.imulab.astrea.domain

import io.imulab.astrea.domain.request.Request
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.support.ClientSupport
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthRequestSpec : Spek({

    describe("merge") {
        it("should merge two requests") {
            val base = Request.Builder().also { b ->
                b.client = ClientSupport.foo()
                b.addScopes("one", "two")
                b.addGrantedScopes("one")
                b.session = DefaultSession()
                b.setForm(mutableMapOf("x" to listOf("1", "2")))
            }.build()

            val toMerge = Request.Builder().also { b ->
                b.client = ClientSupport.bar()
                b.addScopes("three")
                b.addGrantedScopes("three")
                b.session = DefaultSession()
                b.setForm(mutableMapOf("y" to listOf("3", "4")))
            }.build()

            assertThatCode { base.merge(toMerge) }.doesNotThrowAnyException()

            assertThat(base.getClient().getId()).isEqualTo(ClientSupport.bar().getId())
            assertThat(base.getRequestScopes()).contains("one", "two", "three")
            assertThat(base.getGrantedScopes()).contains("one", "three")
            assertThat(base.getRequestForm()).containsEntry("x", listOf("1", "2")).containsEntry("y", listOf("3", "4"))
        }
    }

    describe("sanitize") {
        it("should remove unwanted fields") {
            val dirty = Request.Builder().also { b ->
                b.client = ClientSupport.foo()
                b.setForm(mutableMapOf(
                        "x" to listOf("1"),
                        "y" to listOf("2"),
                        "z" to listOf("3")
                ))
            }.build()
            val sanitized = dirty.sanitize(listOf("x", "z"))

            assertThat(sanitized).isNotSameAs(dirty)
            assertThat(sanitized.getRequestForm()).containsKeys("x", "z").doesNotContainKey("y")
        }
    }
})