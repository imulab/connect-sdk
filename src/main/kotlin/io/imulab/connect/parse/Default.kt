package io.imulab.connect.parse

import io.imulab.connect.*
import io.imulab.connect.client.NothingClient
import io.imulab.connect.client.chooseRedirectUri
import io.imulab.connect.spi.HttpRequest
import java.time.LocalDateTime
import java.util.*

/**
 * An implementation of [AuthorizeRequestParser] and [TokenRequestParser] to set default values.
 *
 * This implementation will merge default values back to the accumulator, and then operate directly
 * on the accumulator to set session values, based on existing values.
 */
class DefaultValueParser : AuthorizeRequestParser, TokenRequestParser {

    override suspend fun parse(httpRequest: HttpRequest, accumulator: AuthorizeRequest) {
        // perform a soft merge in favor of existing values
        accumulator.mergeWith(ConnectAuthorizeRequest(
            id = UUID.randomUUID().toString(),
            requestedAt = LocalDateTime.now(),
            display = Display.PAGE,
            responseMode = ResponseMode.QUERY
        ), hard = false)

        if (accumulator.client !is NothingClient) {
            accumulator.session.clientId = accumulator.client.id
            accumulator.session.savedByRequestId = accumulator.id
            accumulator.session.nonce = accumulator.nonce
            accumulator.session.finalRedirectUri = accumulator.client.chooseRedirectUri(accumulator.redirectUri)
        }
    }

    override suspend fun parse(httpRequest: HttpRequest, accumulator: TokenRequest) {
        // perform a soft merge in favor of existing values
        accumulator.mergeWith(ConnectTokenRequest(
            id = UUID.randomUUID().toString(),
            requestedAt = LocalDateTime.now()
        ), hard = false)

        if (accumulator.client !is NothingClient) {
            accumulator.session.clientId = accumulator.client.id
            accumulator.session.finalRedirectUri = accumulator.redirectUri
        }
    }
}