package io.imulab.connect.parse

import io.imulab.connect.*
import io.imulab.connect.auth.CLIENT_ID
import io.imulab.connect.client.*
import io.imulab.connect.spi.HttpClient
import io.imulab.connect.spi.HttpRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.AesKey
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Parser implementation to resolve request object from 'request' parameter or 'request_uri' parameter.
 *
 * The resolution of the request object follows the following order:
 * 1. from 'request' parameter
 * 2. from pre-cached request object corresponding to 'request_uri' parameter
 * 3. from calling remote endpoint at 'request_uri' parameter
 *
 * If client has registered `request_object_encryption_alg` and `request_object_encryption_enc` and they are not `none`,
 * an attempt of decryption of the resolved request object is performed. When using symmetric algorithm, the decryption
 * key is client's plain text secret; when using asymmetric algorithm, the decryption key is resolved from server's JWKS
 * to find a private key with matching algorithm.
 *
 * If client has registered `request_object_signing_alg`, a signature verification step is performed after we performed
 * or skipped the decryption step based on the above procedure. When `request_object_signing_alg` is not `none`, a
 * verification key is resolved based on the symmetry of the signing algorithm. When the algorithm is symmetric, HS256
 * for instance, client's plain text secret is used as the verification key; When the algorithm is not symmetric, RS256
 * for instance, a public key is selected from client's JWKS with matching algorithm and optionally matching key id.
 *
 * The optionally decrypted and optionally signature verified request object is then parsed to reveal parameters. The
 * resolved parameters are put into a work-in-progress (wip) authorize request and is merged back to the accumulator
 * authorize request based on the option of [mergeBackHard].
 *
 * A note on security: if the request object contained `client_id`, the resolved client will be explicitly compared to
 * that in the accumulator, if any. If their id mismatch, the request will be immediately denied to prevent malicious
 * client posing as other clients in downstream processing.
 *
 * @since inception
 */
class RequestOrUriParser(
    private val clientLookup: ClientLookup,
    private val httpClient: HttpClient,
    private val requestParameterSupported: Boolean,
    private val requestUriParameterSupported: Boolean,
    private val requireRequestUriRegistration: Boolean,
    private val serverJwks: JsonWebKeySet,
    private val issuerUrl: String,
    private val mergeBackHard: Boolean = true
) : AuthorizeRequestParser {

    override suspend fun parse(httpRequest: HttpRequest, accumulator: AuthorizeRequest) {
        try {
            doParse(httpRequest, accumulator)
        } catch (t: Throwable) {
            if (t is ConnectException)
                throw t
            else
                throw Errors.invalidRequest(t.message ?: "invalid request object")
        }
    }

    private suspend fun doParse(httpRequest: HttpRequest, accumulator: AuthorizeRequest) {
        val client = resolveClient(httpRequest, accumulator)
        val request = resolveRequest(httpRequest, client)

        if (request.isEmpty())
            return

        val wip = createWip(expandRequest(request, client))

        /*
         * Explicitly check client id before merging, to avoid attacks where malicious party
         * authenticate with one client but replaces it through the use of request parameter.
         */
        if (tryClient(wip) != null && tryClient(accumulator) != null) {
            val wipClientId = tryClient(wip)!!.id
            val accClientId = tryClient(accumulator)!!.id
            if (wipClientId != accClientId)
                throw Errors.invalidRequest("client_id in request parameter mismatch")
        }

        accumulator.mergeWith(wip, hard = mergeBackHard)
    }

    private suspend fun createWip(claims: JwtClaims): AuthorizeRequest {
        val wip = ConnectAuthorizeRequest(id = "")

        // if client_id, get client asynchronously
        val getClientAsync = claims.getClientId().nonEmptyOrNull()?.let { id ->
            coroutineScope {
                async(Dispatchers.IO) { clientLookup.findById(id) }
            }
        }

        wip.responseTypes.addAll(claims.getResponseTypes())

        wip.redirectUri = claims.getRedirectUri()

        wip.scopes.addAll(claims.getScopes())

        wip.state = claims.getState()

        wip._responseMode = claims.getResponseMode()

        wip._display = claims.getDisplay()

        wip.prompt.addAll(claims.getPrompts())

        wip.maxAge = claims.getMaxAge()

        wip.nonce = claims.getNonce()

        wip.uiLocales.addAll(claims.getUiLocales())

        wip.idTokenHint = claims.getIdTokenHint()

        wip.loginHint = claims.getLoginHint()

        wip.acrValues.addAll(claims.getAcrValues())

        wip.claimsLocales.addAll(claims.getClaimsLocales())

        wip.claims.putAll(
            kotlin.runCatching {
                claims.getClaimValue(CLAIMS, HashMap::class.java) ?: HashMap<String, Any>()
            }.getOrNull()?.mapKeys { it.toString() } ?: emptyMap()
        )

        // if client_id, wait for client result and set it
        getClientAsync?.await().apply { wip._client = this }

        return wip
    }

    private suspend fun resolveClient(httpRequest: HttpRequest, accumulator: AuthorizeRequest): Client {
        return tryClient(accumulator) ?: coroutineScope {
            async(Dispatchers.IO) {
                clientLookup.findById(httpRequest.parameter(CLIENT_ID))
            }
        }.await()
    }

    private suspend fun resolveRequest(httpRequest: HttpRequest, client: Client): String {
        var request = if (requestParameterSupported)
            httpRequest.parameter(REQUEST)
        else ""

        val requestUri = if (requestUriParameterSupported)
            httpRequest.parameter(REQUEST_URI)
        else ""

        // fast path: invalid case or readily available
        when {
            request.isEmpty() && requestUri.isEmpty() -> return ""
            request.isNotEmpty() && requestUri.isNotEmpty() ->
                throw Errors.invalidRequest("only one of request and request_uri may be used.")
            request.isNotEmpty() -> return request
        }

        // slow path: need to resolve request_uri from cache or from remote
        if (requireRequestUriRegistration) {
            if (!client.requestUris.contains(requestUri))
                throw Errors.invalidRequest("request_uri is not registered")
        }

        if (client is RequestCacheAware)
            request = client.uriForRequestCache(requestUri)

        if (request.isEmpty()) {
            request = coroutineScope {
                async(Dispatchers.IO) {
                    httpClient.get(requestUri)
                }
            }.await()

            val fragment = httpClient.fragmentOf(requestUri)
            if (fragment.isNotEmpty()) {
                val hashed = MessageDigest.getInstance("SHA-256")
                    .digest(request.toByteArray(StandardCharsets.UTF_8))
                    .toString(StandardCharsets.UTF_8)
                if (hashed != fragment)
                    throw Errors.invalidRequest("request_uri hash mismtach")
            }
        }

        return request
    }

    private fun expandRequest(request: String, client: Client): JwtClaims {
        var wip = request

        // decrypt
        if (client.requireRequestObjectEncryption()) {
            val decryptionKey = if (client.requestObjectEncryptionAlgorithm.symmetric) {
                AesKey(client.resolvePlainTextSecret().toByteArray(StandardCharsets.UTF_8))
            } else {
                serverJwks.selectKeyForEncryption(client.requestObjectEncryptionAlgorithm).resolvePrivateKey()
            }

            wip = JsonWebEncryption().apply {
                setAlgorithmConstraints(
                    AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                        client.requestObjectEncryptionAlgorithm.value
                    ))
                setContentEncryptionAlgorithmConstraints(
                    AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                        client.requestObjectEncryptionEncoding.value
                    ))
                compactSerialization = wip
                key = decryptionKey
            }.plaintextString
        }

        // signature verification
        return JwtConsumerBuilder().apply {
            setExpectedIssuer(client.id)
            setExpectedAudience(issuerUrl)
            setJwsAlgorithmConstraints(
                AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.WHITELIST,
                    client.requestObjectSigningAlgorithm.value
                )
            )
            when (client.requestObjectSigningAlgorithm) {
                SigningAlgorithm.NONE -> setSkipVerificationKeyResolutionOnNone()
                else -> {
                    setVerificationKey(client.resolveRequestObjectSignatureVerificationKey())
                }
            }
        }.build().processToClaims(wip)
    }
}

internal const val REQUEST: String = "request"
internal const val REQUEST_URI: String = "request_uri"