package io.imulab.astrea.domain

import io.imulab.astrea.support.SessionSupport
import org.assertj.core.api.Assertions.assertThat
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.time.LocalDateTime

object SessionSpec : Spek({

    describe("clone") {

        it("should provide an identical session") {
            val session = SessionSupport.default(username = "test_user", expiry = mapOf(
                    TokenType.AccessToken to LocalDateTime.now().plusDays(1)
            ))
            assertThat(session.clone())
                    .isNotSameAs(session)
                    .isEqualToComparingFieldByFieldRecursively(session)
        }
    }
})