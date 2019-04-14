package io.imulab.connect.client

import io.imulab.connect.Errors

/**
 * Interface for find a client.
 */
interface ClientLookup {
    /**
     * Find a client by its id asynchronously.
     */
    suspend fun findById(id: String): Client
}

/**
 * In memory implementation of a simple [ClientLookup] to be used in tests.
 */
class MemoryClientLookup(private val clients: Map<String, Client> = emptyMap()): ClientLookup {

    constructor(vararg clients: Client): this(clients.associateBy { it.id })

    override suspend fun findById(id: String): Client {
        return clients.getOrElse(id, defaultValue = {
            throw Errors.clientNotFound(id)
        })
    }
}