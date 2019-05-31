package io.imulab.connect.parse

import io.imulab.connect.AuthorizeRequest
import io.imulab.connect.Errors
import io.imulab.connect.TokenRequest
import io.imulab.connect.client.*
import io.imulab.connect.spi.HttpRequest

/**
 * Implementation of [AuthorizeRequestParser] and [TokenRequestParser] that validates the work in progress. This is usually
 * done at the end of all other parsers. This parser does not add in any new parameter values, only validates them.
 */
class ValidatingParser(
    private val scopeComparator: (String, String) -> Boolean = { a, b -> a == b }
) : AuthorizeRequestParser, TokenRequestParser {

    override suspend fun parse(httpRequest: HttpRequest, accumulator: AuthorizeRequest) {
        validate(accumulator)
    }

    private fun validate(request: AuthorizeRequest) {
        must("request id should not be empty") { request.id.isNotEmpty() }
        must("client should not be nothing") { request.client !is NothingClient }
        must("redirect_uri should have been resolved") { request.session.finalRedirectUri.isNotEmpty() }

        request.apply {
            // scope
            if (scopes.isEmpty())
                throw Errors.invalidRequest("scope is required")
            client.mustAcceptAllScopes(scopes, scopeComparator)

            // response_type
            if (responseTypes.isEmpty())
                throw Errors.invalidRequest("response_type is required")
            responseTypes.forEach { client.mustAcceptResponseType(it) }

            // max_age
            if (maxAge < 0)
                throw Errors.invalidRequest("max_age must be non-negative")
        }
    }

    override suspend fun parse(httpRequest: HttpRequest, accumulator: TokenRequest) {
        accumulator.apply {
            // client
            if (client is NothingClient)
                throw Errors.invalidRequest("client_id is required")
            if (redirectUri.isEmpty())
                throw Errors.invalidRequest("redirect_uri is required")

            // grant_type
            if (grantTypes.isEmpty())
                throw Errors.invalidRequest("grant_type is required")
            grantTypes.forEach { client.mustAcceptGrantType(it) }
            if (grantTypes.contains(GrantType.CODE) && code.isEmpty())
                throw Errors.invalidRequest("authorization code is required when grant_type=authorization_code")
            if (grantTypes.contains(GrantType.REFRESH) && refreshToken.isEmpty())
                throw Errors.invalidRequest("refresh token is required when grant_type=refresh_token")
        }
    }

    private fun must(message: String, condition: () -> Boolean) {
        if (!condition())
            throw IllegalStateException(message)
    }
}