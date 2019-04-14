package io.imulab.connect

import io.imulab.connect.client.GrantType
import io.imulab.connect.client.ResponseType

/**
 * Exception information defined in Open ID Connect 1.0.
 */
class ConnectException(
    val error: String,
    private val description: String,
    val statusCode: Int = 500,
    val headers: Map<String, String> = emptyMap()
) : RuntimeException("$error : $description") {

    fun toMap(): Map<String, String> = mapOf(
        "error" to error,
        "error_description" to description
    )
}

/**
 * Factory object to create [ConnectException].
 */
object Errors {

    fun invalidRequestError(description: String): ConnectException = ConnectException(
        error = Codes.invalidRequest,
        description = description,
        statusCode = 400
    )

    fun unsupportedGrantType(grantType: GrantType): ConnectException = ConnectException(
        error = Codes.unsupportedGrantType,
        description = "grant_type ${grantType.value} is not supported.",
        statusCode = 400
    )

    fun unsupportedResponseType(responseType: ResponseType): ConnectException = ConnectException(
        error = Codes.unsupportedResponseType,
        description = "response_type ${responseType.value} is not supported.",
        statusCode = 400
    )

    fun invalidScope(scope: String = ""): ConnectException {
        val message = if (scope.isEmpty())
            "scope is invalid or not accepted." else "scope $scope is invalid or not accepted."
        return ConnectException(
            error = Codes.invalidScope,
            description = message,
            statusCode = 400
        )
    }

    fun clientNotFound(id: String): ConnectException = ConnectException(
        error = Codes.invalidClient,
        description = "client with id $id is not found.",
        statusCode = 400
    )

    fun invalidGrant(reason: String): ConnectException {
        return ConnectException(
            error = Codes.invalidGrant,
            description = reason,
            statusCode = 400
        )
    }

    fun serverError(reason: String): ConnectException {
        return ConnectException(
            error = Codes.serverError,
            description = reason,
            statusCode = 500
        )
    }

    object Codes {
        const val invalidRequest = "invalid_request"
        const val invalidClient = "invalid_client"
        const val invalidGrant = "invalid_grant"
        const val unauthorizedClient = "unauthorized_client"
        const val unsupportedGrantType = "unsupported_grant_type"
        const val unsupportedResponseType = "unsupported_response_type"
        const val invalidScope = "invalid_scope"
        const val accessDenied = "access_denied"
        const val serverError = "server_error"
    }
}