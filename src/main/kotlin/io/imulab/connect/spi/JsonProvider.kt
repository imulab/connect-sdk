package io.imulab.connect.spi

/**
 * Service provider interface for JSON capabilities
 */
interface JsonProvider {

    /**
     * Deserialize a [raw] JSON into a map.
     */
    fun deserialize(raw: String): Map<String, Any>
}