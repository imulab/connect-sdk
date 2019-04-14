package io.imulab.connect.handler

import io.imulab.connect.AuthorizeRequest
import io.imulab.connect.Response
import io.imulab.connect.TokenRequest

/**
 * Handles request on the authorization endpoint.
 */
interface AuthorizeHandler {
    /**
     * Fulfill the authorization request.
     */
    suspend fun authorize(request: AuthorizeRequest, response: Response)

    /**
     * Returns true if this handler can handle the request.
     */
    fun supports(request: AuthorizeRequest): Boolean
}

/**
 * Handles request on the token endpoint.
 */
interface TokenHandler {

    /**
     * Update or revive the session based on the token request.
     */
    suspend fun updateSession(request: TokenRequest)

    /**
     * Attempt to issue the requested token.
     */
    suspend fun issueToken(request: TokenRequest, response: Response)

    /**
     * Returns true if this handler can handle the request.
     */
    fun supports(request: TokenRequest): Boolean
}