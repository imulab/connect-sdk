package io.imulab.connect.auth

import io.imulab.connect.Errors
import io.imulab.connect.TokenRequest
import io.imulab.connect.client.AuthenticationMethod
import io.imulab.connect.spi.HttpRequest

const val POST = "POST"
const val CLIENT_ID = "client_id"

/**
 * Interface for performing authentication on token endpoint. This should be used before the request is completely
 * parsed.
 */
interface Authenticator {

    /**
     * Perform authentication on the [httpRequest]. If any useful information is extracted during the authentication
     * process, saved it into the [request], which can be merged with other sources later.
     */
    suspend fun authenticate(httpRequest: HttpRequest, request: TokenRequest)

    /**
     * Informational method to return the [AuthenticationMethod] this authenticator implements.
     */
    fun implements(): List<AuthenticationMethod>

    /**
     * Test method to return true if the provided [httpRequest] can be authenticated by this authenticator.
     */
    fun supports(httpRequest: HttpRequest): Boolean
}

/**
 * Main entry point for authentication.
 */
class AuthenticationHandler(
    private val authenticators: List<Authenticator>,
    private val noneAuthenticator: NoneAuthenticator
) {

    suspend fun authenticate(httpRequest: HttpRequest, request: TokenRequest) {
        authenticators.forEach { it.authenticate(httpRequest, request) }
        if (!isClientSet(request))
            noneAuthenticator.authenticate(httpRequest, request)
        if (!isClientSet(request))
            throw Errors.clientForbidden("failed to determine how to authenticate client.")
    }
}

/**
 * Utility extension to test if the client is already set. If client set, we can simply skip the current authenticator
 * even when entry condition are met.
 */
internal fun isClientSet(request: TokenRequest): Boolean =
    kotlin.runCatching { request.client }.getOrNull() != null