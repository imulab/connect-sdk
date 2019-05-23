package io.imulab.connect

import io.imulab.connect.client.NothingClient
import io.imulab.connect.client.mustAcceptGrantType
import io.imulab.connect.client.mustAcceptResponseType
import io.imulab.connect.spi.Discovery
import io.imulab.connect.spi.mustAcceptGrantType
import io.imulab.connect.spi.mustAcceptResponseType

/**
 * Extension to perform simple validation on [AuthorizeRequest]
 */
fun AuthorizeRequest.validate(discovery: Discovery) {
    ensureClient()
    checkResponseTypes(discovery)
    maxAgeMustBeNonNegative()
    ensureSubject()
    ensureFinalRedirectUri()
    ensureNoRougeGrantedScopes()
}

private fun Request.ensureClient() {
    if (client is NothingClient)
        throw Errors.invalidRequest("client_id is required.")
    if (client.id != session.clientId)
        throw Errors.serverError("client_id and session client_id mismatch")
}

private fun AuthorizeRequest.checkResponseTypes(discovery: Discovery) {
    if (responseTypes.isEmpty())
        throw Errors.invalidRequest("response_type is required.")
    responseTypes.forEach { client.mustAcceptResponseType(it) }
    responseTypes.forEach { discovery.mustAcceptResponseType(it) }
}

private fun AuthorizeRequest.maxAgeMustBeNonNegative() {
    if (maxAge < 0L)
        throw Errors.invalidRequest("max_age is invalid")
}

private fun AuthorizeRequest.ensureSubject() {
    if (session.subject.isEmpty())
        throw Errors.invalidRequest("subject is not set")
    if (session.obfuscatedSubject.isEmpty())
        throw Errors.serverError("obfuscated subject is not set")
}

private fun AuthorizeRequest.ensureFinalRedirectUri() {
    if (session.finalRedirectUri.isEmpty())
        throw Errors.serverError("redirect_uri is not determined")
}

private fun AuthorizeRequest.ensureNoRougeGrantedScopes() {
    if (!scopes.containsAll(session.grantedScopes))
        throw Errors.invalidScope("rouge granted scopes found")
}

/**
 * Extension to perform simple validation on [TokenRequest]
 */
fun TokenRequest.validate(discovery: Discovery) {
    ensureClient()
    ensureRedirectUri()
    checkGrantTypes(discovery)
}

private fun TokenRequest.ensureRedirectUri() {
    if (redirectUri.isEmpty())
        throw Errors.invalidScope("redirect_uri is required")
}

private fun TokenRequest.checkGrantTypes(discovery: Discovery) {
    if (grantTypes.isEmpty())
        throw Errors.invalidRequest("grant_type is required.")
    grantTypes.forEach { client.mustAcceptGrantType(it) }
    grantTypes.forEach { discovery.mustAcceptGrantType(it) }
}