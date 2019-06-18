package io.imulab.connect.parse

import io.imulab.connect.Errors
import io.imulab.connect.spi.HttpRequest

/**
 * Utility method to force existence check on a parameter.
 */
suspend fun HttpRequest.mustString(name: String): String {
    val v = this.parameter(name)
    if (v.isEmpty())
        throw Errors.invalidRequest("$name is required")
    return v
}

/**
 * Utility method to space into spaces. Also prevents edge case of multiple consecutive spaces.
 */
fun String.spaceSplit(): List<String> = this.split(SPACE).filter { it.isNotEmpty() }

/**
 * Utility method to chain default value.
 */
fun String.withDefault(default: String): String = if (isEmpty()) default else this

internal const val SPACE = " "