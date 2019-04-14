package io.imulab.connect.client

import io.imulab.connect.Errors
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jwk.JsonWebKeySet

/**
 * Utility method to test if [responseType] is registered by client
 */
fun Client.acceptsResponseType(responseType: ResponseType): Boolean =
    this.responseTypes.contains(responseType)

/**
 * Utility method to force test if [responseType] is registered by client. If not, an exception is thrown.
 */
fun Client.mustAcceptResponseType(responseType: ResponseType) {
    if (!this.acceptsResponseType(responseType))
        throw Errors.unsupportedResponseType(responseType)
}

/**
 * Utility method to test if [grantType] is registered by client.
 */
fun Client.acceptsGrantType(grantType: GrantType): Boolean =
    this.grantTypes.contains(grantType)

/**
 * Utility method to force test if [grantType] is registered by client. If not, an exception is thrown.
 */
fun Client.mustAcceptGrantType(grantType: GrantType) {
    if (!this.acceptsGrantType(grantType))
        throw Errors.unsupportedGrantType(grantType)
}

/**
 * Utility method to test if [scope] can be accepted by client. Acceptance is decided using
 * [comparator], which defaults to string equality comparison.
 */
fun Client.acceptsScope(
    scope: String,
    comparator: (registered: String, supplied: String) -> Boolean = { r, s -> r == s }
): Boolean {
    return this.scopes.any { comparator(it, scope) }
}

/**
 * Utility method to test if [scopes] are all accepted by client. Acceptance is decided using
 * [comparator], which defaults to string equality comparison.
 */
fun Client.acceptsAllScopes(
    scopes: Collection<String>,
    comparator: (registered: String, supplied: String) -> Boolean = { r, s -> r == s }
): Boolean {
    return scopes.all { this.acceptsScope(it, comparator) }
}

/**
 * Utility method to force test if all [scopes] are accepted by client. If not, an exception is thrown.
 */
fun Client.mustAcceptAllScopes(
    scopes: Collection<String>,
    comparator: (registered: String, supplied: String) -> Boolean = { r, s -> r == s }
) {
    if (!this.acceptsAllScopes(scopes, comparator))
        throw Errors.invalidScope()
}

/**
 * Utility method to determine whether id token requires encryption.
 */
fun Client.requireIdTokenEncryption(): Boolean =
    this.idTokenEncryptedResponseAlgorithm != EncryptionAlgorithm.NONE &&
        this.idTokenEncryptedResponseEncoding != EncryptionEncoding.NONE

/**
 * Utility method to fetch and/or parse json web key set.
 */
fun Client.resolveJwks(): JsonWebKeySet {
    if (this is JwksCacheAware)
        return JsonWebKeySet(this.jwksCache)

    if (this.jwks.isNotEmpty())
        return JsonWebKeySet(this.jwks)

    return JsonWebKeySet(HttpsJwks(this.jwksUri).jsonWebKeys)
}