package io.imulab.connect.spi

/**
 * Service provider interface for an http request. Operation on this object should be idempotent.
 */
interface HttpRequest {

    /**
     * Returns the HTTP method in capital letters.
     */
    fun method(): String

    /**
     * Returns header value for the given [key]. If such header does not exist, returns an empty string.
     */
    fun header(key: String): String

    /**
     * Returns the parameter value for the given [key]. Parameter can be source from either query when [method] is
     * `GET`, or from body form when [method] is `POST`. If a parameter does not exist, return an empty string.
     */
    fun parameter(key: String): String
}