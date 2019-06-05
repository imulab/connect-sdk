package io.imulab.connect.parse

import io.imulab.connect.*
import io.imulab.connect.auth.CLIENT_ID
import io.imulab.connect.client.*
import io.imulab.connect.spi.HttpRequest
import io.imulab.connect.spi.JsonProvider
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

/**
 * Implementation of [AuthorizeRequestParser] that parse the `client_id` and `redirect_uri` parameter ahead of
 * everything else.
 *
 * The reason to separate this step is that we will gain knowledge of the client identity and the redirection uri,
 * so if anything goes wrong after this step, we will be able to do a redirection, rather than reporting error through
 * status 400.
 *
 * We are only implementing [AuthorizeRequestParser] because the advantage of this separation only pertains to the
 * authorize request. Error reporting of the token request all go through the response body.
 */
class ClientDetailsParser(
    private val clientLookup: ClientLookup,
    private val mergeBackHard: Boolean = true
) : AuthorizeRequestParser {

    override suspend fun parse(httpRequest: HttpRequest, accumulator: AuthorizeRequest) {
        try {
            val wip = ConnectAuthorizeRequest(id = "")

            // REQUIRED: client_id
            if (accumulator.client is NothingClient && httpRequest.parameter(CLIENT_ID).isNotEmpty())
                wip.client = getClient(httpRequest).await()

            // OPTIONAL: redirect_uri
            wip.redirectUri = httpRequest.parameter(REDIRECT_URI)

            // Pick the redirect_uri now as later steps depend on it
            val finalRedirectUri = wip.client.chooseRedirectUri(wip.redirectUri)
            accumulator.session.finalRedirectUri = finalRedirectUri

            // merge back
            accumulator.mergeWith(wip, hard = mergeBackHard)
        } catch (t: Throwable) {
            throw Errors.invalidRequest(t.message ?: "failed to parse request.")
        }
    }

    private suspend fun getClient(httpRequest: HttpRequest): Deferred<Client> {
        return coroutineScope {
            async {
                clientLookup.findById(httpRequest.mustString(CLIENT_ID))
            }
        }
    }
}

/**
 * Implementation of [AuthorizeRequestParser] and [TokenRequestParser] to parse request parameters directly from
 * the HTTP request.
 *
 * This implementation tries its best to acquire parameters. However, it tries not to raise error related to missing
 * required parameters as they could be sourced by other parsers.
 *
 * The only requirement is that client and its redirect_uri must be already parsed.
 *
 * Once the parameters are acquired, it will merge them back into the accumulator request, which means all non-null
 * and non-empty field will replace that of the accumulator values. This is done because, while this parser may not be
 * complete, its answers are authoritative.
 */
class SimpleParameterParser(
    private val clientLookup: ClientLookup,
    private val jsonProvider: JsonProvider,
    private val mergeBackHard: Boolean = true
) : AuthorizeRequestParser, TokenRequestParser {

    override suspend fun parse(httpRequest: HttpRequest, accumulator: AuthorizeRequest) {
        if (accumulator.client is NothingClient)
            throw IllegalStateException("A previous parser should have resolved the client or reported error.")
        else if (accumulator.session.finalRedirectUri.isEmpty())
            throw IllegalStateException("A previous parser should have resolved redirect_uri or reported error.")

        try {
            val wip = doParse(httpRequest)
            accumulator.mergeWith(wip, hard = mergeBackHard)
        } catch (t: Throwable) {
            throw Errors.invalidRequest(t.message ?: "failed to parse request.")
        }
    }

    private suspend fun doParse(httpRequest: HttpRequest): AuthorizeRequest {
        val wip = ConnectAuthorizeRequest(id = "")

        // REQUIRED: response_type
        wip.responseTypes.addAll(
            httpRequest.parameter(RESPONSE_TYPE).spaceSplit().map { ResponseType.parse(it) }.toSet()
        )

        // OPTIONAL: scope
        wip.scopes.addAll(httpRequest.parameter(SCOPE).spaceSplit().toSet())

        // RECOMMENDED: state
        wip.state = httpRequest.parameter(STATE)

        // OPTIONAL: response_mode, default to QUERY
        wip.responseMode = ResponseMode.parse(
            httpRequest.parameter(RESPONSE_MODE).withDefault(ResponseMode.QUERY.value)
        )

        // OPTIONAL: display, default to PAGE
        wip.display = Display.parse(
            httpRequest.parameter(DISPLAY).withDefault(Display.PAGE.value)
        )

        // OPTIONAL: prompt
        wip.prompt.addAll(httpRequest.parameter(PROMPT).spaceSplit().map { Prompt.parse(it) }.toSet())

        // OPTIONAL: max_age
        wip.maxAge = httpRequest.parameter(MAX_AGE).toLongOrNull() ?: 0L

        // OPTIONAL: nonce
        wip.nonce = httpRequest.parameter(NONCE)

        // OPTIONAL: ui_locales
        wip.uiLocales.addAll(httpRequest.parameter(UI_LOCALES).spaceSplit())

        // OPTIONAL: id_token_hint
        wip.idTokenHint = httpRequest.parameter(ID_TOKEN_HINT)

        // OPTIONAL: login_hint
        wip.loginHint = httpRequest.parameter(LOGIN_HINT)

        // OPTIONAL: acr_values
        wip.acrValues.addAll(httpRequest.parameter(ACR_VALUES).spaceSplit())

        // OPTIONAL: claims
        wip.claims.putAll(parseClaims(httpRequest.parameter(CLAIMS)))

        // OPTIONAL: claims_locales
        wip.claimsLocales.addAll(httpRequest.parameter(CLAIMS_LOCALES).spaceSplit())

        /*
         * this parser stops here. 'request', 'request_uri' parameter are handled by another
         * parser since they can expand into an entire request that is to be merged back into
         * this one.
         */

        return wip
    }

    override suspend fun parse(httpRequest: HttpRequest, accumulator: TokenRequest) {
        val wip = ConnectTokenRequest(id = "")

        // REQUIRED: client_id
        if (accumulator.client is NothingClient && httpRequest.parameter(CLIENT_ID).isNotEmpty())
            wip.client = getClient(httpRequest).await()

        // REQUIRED: redirect_uri
        wip.redirectUri = httpRequest.parameter(REDIRECT_URI)

        // REQUIRED: grant_type
        wip.grantTypes.addAll(httpRequest.parameter(GRANT_TYPE).spaceSplit().map { GrantType.parse(it) })

        // REQUIRED: scope
        wip.scopes.addAll(httpRequest.parameter(SCOPE).spaceSplit())

        // OPTIONAL: code
        wip.code = httpRequest.parameter(CODE)

        // OPTIONAL: refresh_token
        wip.refreshToken = httpRequest.parameter(REFRESH_TOKEN)

        accumulator.mergeWith(wip, hard = true)
    }

    private suspend fun getClient(httpRequest: HttpRequest): Deferred<Client> {
        return coroutineScope {
            async {
                clientLookup.findById(httpRequest.mustString(CLIENT_ID))
            }
        }
    }

    private fun parseClaims(raw: String): Map<String, Any> {
        if (raw.isBlank())
            return emptyMap()
        return jsonProvider.deserialize(raw)
    }
}

internal const val REFRESH_TOKEN = "refresh_token"
internal const val CODE = "code"
internal const val GRANT_TYPE = "grant_type"
internal const val RESPONSE_TYPE = "response_type"
internal const val REDIRECT_URI = "redirect_uri"
internal const val SCOPE = "scope"
internal const val STATE = "state"
internal const val RESPONSE_MODE = "response_mode"
internal const val DISPLAY = "display"
internal const val PROMPT = "prompt"
internal const val MAX_AGE = "max_age"
internal const val UI_LOCALES = "ui_locales"
internal const val ID_TOKEN_HINT = "id_token_hint"
internal const val LOGIN_HINT = "login_hint"
internal const val ACR_VALUES = "acr_values"
internal const val CLAIMS = "claims"
internal const val CLAIMS_LOCALES = "claims_locales"
internal const val NONCE = "nonce"