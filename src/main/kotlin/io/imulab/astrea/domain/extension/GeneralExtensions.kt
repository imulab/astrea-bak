package io.imulab.astrea.domain.extension

import io.imulab.astrea.error.RequestParameterMissingException
import org.jose4j.jwt.NumericDate
import java.time.LocalDateTime
import java.time.ZoneOffset

/**
 * Requires the list of iterable provided by [this] be contained in the collection named [universe].
 *
 * When any element is not in [universe], this method throws [IllegalArgumentException] with the string representation
 * of the invalid element. Caller can provide a custom [exceptionEnhancer] to enhance the exception with more context.
 *
 * If all element is in [universe], this method returns the list representation of [this].
 */
inline fun <reified T : Any> Iterable<T>.mustBeIn(
        universe: Collection<T>,
        noinline exceptionEnhancer: ((IllegalArgumentException) -> Throwable)? = null
): List<T> {
    val notIn = this.find { !universe.contains(it) }
    if (notIn != null)
        throw IllegalArgumentException(notIn.toString()).let {
            if (exceptionEnhancer != null)
                exceptionEnhancer(it)
            else
                it
        }
    return this.toList()
}

// utility extension to allow fluent string checking
fun String?.requireNotNullOrEmpty(
        parameterName: String,
        exceptionEnhancer: ((RequestParameterMissingException) -> Throwable)? = null
): String {
    if (this == null || this.isEmpty())
        throw RequestParameterMissingException(parameterName)
                .let { if (exceptionEnhancer != null) exceptionEnhancer(it) else it }
    return this
}

fun NumericDate.toLocalDateTime(): LocalDateTime {
    return LocalDateTime.ofEpochSecond(this.value, 0, ZoneOffset.UTC)
}