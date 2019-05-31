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

    /* oauth errors */

    /**
     * The request is missing a required parameter, includes an
     * invalid parameter value, includes a parameter more than
     * once, or is otherwise malformed.
     */
    fun invalidRequest(description: String): ConnectException = ConnectException(
        error = Codes.invalidRequest,
        description = description,
        statusCode = 400
    )

    /**
     * The authorization grant type is not supported by the authorization server.
     */
    fun unsupportedGrantType(grantType: GrantType): ConnectException = ConnectException(
        error = Codes.unsupportedGrantType,
        description = "grant_type '${grantType.value}' is not supported.",
        statusCode = 400
    )

    /**
     * The authorization server does not support obtaining an
     * authorization code using this method.
     */
    fun unsupportedResponseType(responseType: ResponseType): ConnectException = ConnectException(
        error = Codes.unsupportedResponseType,
        description = "response_type '${responseType.value}' is not supported.",
        statusCode = 400
    )

    /**
     * The requested scope is invalid, unknown, or malformed.
     */
    fun invalidScope(scope: String = ""): ConnectException {
        val message = if (scope.isEmpty())
            "scope is invalid or not accepted." else "scope '$scope' is invalid or not accepted."
        return ConnectException(
            error = Codes.invalidScope,
            description = message,
            statusCode = 400
        )
    }

    /**
     * Client does not exist in database.
     */
    fun clientNotFound(id: String): ConnectException = ConnectException(
        error = Codes.invalidClient,
        description = "client with id $id is not found.",
        statusCode = 400
    )

    /**
     * Client fails token endpoint authentication
     */
    fun clientForbidden(reason: String, headers: Map<String, String> = emptyMap()): ConnectException = ConnectException(
        error = Codes.invalidClient,
        description = reason,
        statusCode = 401,
        headers = headers
    )

    /**
     * The provided authorization grant (e.g., authorization
     * code, resource owner credentials) or refresh token is
     * invalid, expired, revoked, does not match the redirection
     * URI used in the authorization request, or was issued to
     * another client.
     */
    fun invalidGrant(reason: String): ConnectException {
        return ConnectException(
            error = Codes.invalidGrant,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The resource owner or authorization server denied the request.
     */
    fun accessDenied(reason: String): ConnectException {
        return ConnectException(
            error = Codes.accessDenied,
            description = reason,
            statusCode = 403
        )
    }

    /**
     * The authenticated client is not authorized to use this
     * authorization grant type.
     */
    fun unauthorizedClient(reason: String): ConnectException {
        return ConnectException(
            error = Codes.unauthorizedClient,
            description = reason,
            statusCode = 403
        )
    }

    /**
     * The authorization server encountered an unexpected
     * condition that prevented it from fulfilling the request.
     * (This error code is needed because a 500 Internal Server
     * Error HTTP status code cannot be returned to the client
     * via an HTTP redirect.)
     */
    fun serverError(reason: String): ConnectException {
        return ConnectException(
            error = Codes.serverError,
            description = reason,
            statusCode = 500
        )
    }

    /* open id connect errors */

    /**
     * The Authorization Server requires End-User interaction of some form to proceed.
     * This error MAY be returned when the prompt parameter value in the Authentication Request
     * is none, but the Authentication Request cannot be completed without displaying a user
     * interface for End-User interaction.
     */
    fun interactionRequired(
        reason: String = "User interaction is required to complete this request."
    ): ConnectException {
        return ConnectException(
            error = Codes.interactionRequired,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The Authorization Server requires End-User authentication. This error MAY be returned when
     * the prompt parameter value in the Authentication Request is none, but the Authentication Request
     * cannot be completed without displaying a user interface for End-User authentication.
     */
    fun loginRequired(
        reason: String = "User is required to login in order to complete this request."
    ): ConnectException {
        return ConnectException(
            error = Codes.loginRequired,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The End-User is REQUIRED to select a session at the Authorization Server. The End-User MAY be
     * authenticated at the Authorization Server with different associated accounts, but the End-User
     * did not select a session. This error MAY be returned when the prompt parameter value in the
     * Authentication Request is none, but the Authentication Request cannot be completed without
     * displaying a user interface to prompt for a session to use.
     */
    fun accountSelectionRequired(
        reason: String = "Multiple accounts are present. User is required to select one in order to complete this request."
    ): ConnectException {
        return ConnectException(
            error = Codes.accountSelectionRequired,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The Authorization Server requires End-User consent. This error MAY be returned when the prompt
     * parameter value in the Authentication Request is none, but the Authentication Request cannot be
     * completed without displaying a user interface for End-User consent.
     */
    fun consentRequired(
        reason: String = "User consent is required in order to complete this request."
    ): ConnectException {
        return ConnectException(
            error = Codes.consentRequired,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The request_uri in the Authorization Request returns an error or contains invalid data.
     */
    fun invalidRequestUri(
        reason: String = "parameter 'request_uri' is invalid or it contains invalid data"
    ): ConnectException {
        return ConnectException(
            error = Codes.invalidRequestUri,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The request parameter contains an invalid Request Object.
     */
    fun invalidRequestObject(
        reason: String = "parameter 'request' is invalid or it contains invalid data"
    ): ConnectException {
        return ConnectException(
            error = Codes.invalidRequestObject,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The OP does not support use of the request parameter.
     */
    fun requestNotSupported(
        reason: String = "The use of 'request' parameter is not supported."
    ): ConnectException {
        return ConnectException(
            error = Codes.requestNotSupported,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The OP does not support use of the request_uri parameter.
     */
    fun requestUriNotSupported(
        reason: String = "The use of 'request_uri' parameter is not supported."
    ): ConnectException {
        return ConnectException(
            error = Codes.requestUriNotSupported,
            description = reason,
            statusCode = 400
        )
    }

    /**
     * The OP does not support use of the registration parameter.
     */
    fun registrationNotSupported(
        reason: String = "The use of 'registration' parameter is not supported."
    ): ConnectException {
        return ConnectException(
            error = Codes.registrationNotSupported,
            description = reason,
            statusCode = 400
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

        const val interactionRequired = "interaction_required"
        const val loginRequired = "login_required"
        const val accountSelectionRequired = "account_selection_required"
        const val consentRequired = "consent_required"
        const val invalidRequestUri = "invalid_request_uri"
        const val invalidRequestObject = "invalid_request_object"
        const val requestNotSupported = "request_not_supported"
        const val requestUriNotSupported = "request_uri_not_supported"
        const val registrationNotSupported = "registration_not_supported"
    }
}