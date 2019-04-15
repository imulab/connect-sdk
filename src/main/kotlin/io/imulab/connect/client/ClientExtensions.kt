package io.imulab.connect.client

import io.imulab.connect.Errors
import io.imulab.connect.resolvePublicKey
import io.imulab.connect.selectKeyForSignature
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.keys.AesKey
import java.nio.charset.StandardCharsets
import java.security.Key

/**
 * Utility method to select redirect_uri.
 */
fun Client.chooseRedirectUri(requestedUri: String): String {
    return if (requestedUri.isEmpty()) {
        when (redirectUris.size) {
            1 -> redirectUris.first()
            else -> throw Errors.invalidRequest("unable to determine redirect_uri")
        }
    } else {
        if (redirectUris.isNotEmpty() && !redirectUris.contains(requestedUri))
            throw Errors.invalidRequest("unable to determine redirect_uri")
        requestedUri
    }
}

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
 * Utility method to determine whether request object is encrypted.
 */
fun Client.requireRequestObjectEncryption(): Boolean =
    this.requestObjectEncryptionAlgorithm != EncryptionAlgorithm.NONE &&
        this.requestObjectEncryptionEncoding != EncryptionEncoding.NONE

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

/**
 * Utility method to find client's plain text secret
 */
fun Client.resolvePlainTextSecret(): String {
    return (this as? ClientSecretAware)?.plainTextSecret()
        ?: throw Errors.serverError("unable to determine client's plain text secret")
}

/**
 * Utility method to determine client's signature verification key for the request object.
 * When request object signing algorithm is symmetric (i.e. HS256), the client's plain text secret is
 * used as the key. When the algorithm is non-symmetric (i.e. RS256), a public key with matching algorithm
 * selected from the client's registered JWKS is used.
 */
fun Client.resolveRequestObjectSignatureVerificationKey(): Key {
    return if (this.requestObjectSigningAlgorithm.symmetric) {
        AesKey(resolvePlainTextSecret().toByteArray(StandardCharsets.UTF_8))
    } else {
        this.resolveJwks().selectKeyForSignature(id, this.requestObjectSigningAlgorithm).resolvePublicKey()
    }
}