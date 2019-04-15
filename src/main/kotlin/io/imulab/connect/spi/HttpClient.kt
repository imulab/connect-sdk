package io.imulab.connect.spi

/**
 * Service provider interface for an client capable of making HTTP requests.
 */
interface HttpClient {

    /**
     * Perform simple HTTP get on the given [url] and returns body as string.
     */
    suspend fun get(url: String): String

    /**
     * Returns the fragment of an [url], or an empty string if url contains no fragment.
     */
    fun fragmentOf(url: String): String
}