package io.imulab.connect.handler

import io.imulab.connect.AuthorizeRequest
import io.imulab.connect.Errors
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

/**
 * Entry point for handling any type of flows.
 */
class ConnectHandler(
    private val authorizeHandlers: List<AuthorizeHandler>,
    private val tokenHandlers: List<TokenHandler>
) {
    suspend fun handleAuthorizeRequest(request: AuthorizeRequest, response: Response) {
        authorizeHandlers.forEach { it.authorize(request, response) }
        if (!request.hasAllResponseTypesBeenHandled())
            throw Errors.serverError("unable to handle all response types")
    }

    suspend fun handleTokenRequest(request: TokenRequest, response: Response) {
        tokenHandlers.forEach { it.updateSession(request) }
        tokenHandlers.forEach { it.issueToken(request, response) }
    }
}