package io.imulab.connect.parse

import io.imulab.connect.AuthorizeRequest
import io.imulab.connect.TokenRequest
import io.imulab.connect.spi.HttpRequest

/**
 * Provides functionality to parse an incoming authorization request.
 */
interface AuthorizeRequestParser {

    /**
     * Parse the data from [httpRequest] and merge that into [accumulator]. Implementations
     * are expected to create their own [AuthorizeRequest] instance and merge that back to
     * [accumulator] when finished.
     */
    suspend fun parse(httpRequest: HttpRequest, accumulator: AuthorizeRequest)
}

interface TokenRequestParser {

    /**
     * Parse the data from [httpRequest] and merge that into [accumulator]. Implementations are
     * expected to create their own [TokenRequest] instance and merge that back to [accumulator]
     * when done.
     */
    suspend fun parse(httpRequest: HttpRequest, accumulator: TokenRequest)
}