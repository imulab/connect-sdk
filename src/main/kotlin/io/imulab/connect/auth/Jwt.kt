package io.imulab.connect.auth

import io.imulab.connect.ConnectTokenRequest
import io.imulab.connect.Errors
import io.imulab.connect.TokenRequest
import io.imulab.connect.client.*
import io.imulab.connect.spi.HttpRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.AesKey
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver
import java.nio.charset.StandardCharsets

const val CLIENT_ASSERTION = "client_assertion"
const val CLIENT_ASSERTION_TYPE = "client_assertion_type"
const val CLIENT_ASSERTION_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

/**
 * This authenticator handles both client_secret_jwt and private_key_jwt authentication method (because their entry
 * condition is the same).
 */
class ClientJwtAuthenticator(
    private val clientLookup: ClientLookup,
    private val tokenEndpointUrl: String
) : Authenticator {

    override suspend fun authenticate(httpRequest: HttpRequest, request: TokenRequest) {
        if (!supports(httpRequest))
            return
        else if (isClientSet(request))
            return

        val client = findClient(getClientId(httpRequest))
        val assertion = httpRequest.parameter(CLIENT_ASSERTION)

        when (client.tokenEndpointAuthMethod) {
            AuthenticationMethod.JWT_SECRET -> {
                verifyAssertionWithClientSecret(assertion, client)
            }
            AuthenticationMethod.JWT_PRIVATE -> {
                verifyAssertionWithClientJwks(assertion, client)
            }
            else -> return
        }

        request.mergeWith(ConnectTokenRequest(id = "", client = client))
    }

    private suspend fun getClientId(httpRequest: HttpRequest): String {
        var clientId = httpRequest.parameter(CLIENT_ID)
        if (clientId.isNotEmpty())
            return clientId

        // if client_id parameter is not included, we will have to dig it from client_assertion the hard way
        try {
            clientId = JwtConsumerBuilder().also { b ->
                b.setSkipAllValidators()
                b.setDisableRequireSignature()
                b.setSkipSignatureVerification()
            }.build().processToClaims(httpRequest.parameter(CLIENT_ASSERTION)).issuer
        } catch (t: Throwable) {
            throw Errors.clientForbidden("failed to process client_assertion")
        }

        if (clientId.isEmpty())
            throw Errors.clientForbidden("unable to determine client identity")
        return clientId
    }

    private suspend fun findClient(id: String): Client {
        return kotlin.runCatching {
            runBlocking {
                async(Dispatchers.IO) { clientLookup.findById(id) }
            }.await()
        }.getOrElse {
            throw Errors.clientForbidden("unable to verify client identity")
        }.apply {
            if (!listOf(
                    AuthenticationMethod.JWT_PRIVATE,
                    AuthenticationMethod.JWT_SECRET
                ).contains(tokenEndpointAuthMethod)) {
                throw Errors.clientForbidden("client is not registered to use JWT based authentication")
            }
        }
    }

    private fun verifyAssertionWithClientSecret(assertion: String, client: Client) {
        client as? ClientSecretAware
            ?: throw Errors.clientForbidden("unable to determine client secret")

        try {
            JwtConsumerBuilder().also { b ->
                b.setRequireJwtId()
                b.setExpectedIssuer(client.id)
                b.setExpectedSubject(client.id)
                b.setExpectedAudience(tokenEndpointUrl)
                b.setRequireExpirationTime()
                b.setVerificationKey(AesKey(client.plainTextSecret().toByteArray(StandardCharsets.UTF_8)))
                b.setJwsAlgorithmConstraints(AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.WHITELIST,
                    client.tokenEndpointAuthSigningAlgorithm.value
                ))
            }.build().process(assertion)
        } catch (t: Throwable) {
            throw Errors.clientForbidden("failed to verify client_assertion: ${t.message}")
        }
    }

    private fun verifyAssertionWithClientJwks(assertion: String, client: Client) {
        try {
            val jwks = client.resolveJwks()
            JwtConsumerBuilder().also { b ->
                b.setRequireJwtId()
                b.setExpectedIssuer(client.id)
                b.setExpectedSubject(client.id)
                b.setExpectedAudience(tokenEndpointUrl)
                b.setRequireExpirationTime()
                b.setVerificationKeyResolver(JwksVerificationKeyResolver(jwks.jsonWebKeys))
                b.setJwsAlgorithmConstraints(AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.WHITELIST,
                    client.tokenEndpointAuthSigningAlgorithm.value
                ))
            }.build().process(assertion)
        } catch (t: Throwable) {
            throw Errors.clientForbidden("failed to verify client_assertion: ${t.message}")
        }
    }

    override fun implements(): List<AuthenticationMethod> = listOf(
        AuthenticationMethod.JWT_SECRET,
        AuthenticationMethod.JWT_PRIVATE
    )

    override suspend fun supports(httpRequest: HttpRequest): Boolean {
        return httpRequest.method() == POST &&
            httpRequest.parameter(CLIENT_ASSERTION).isNotEmpty() &&
            httpRequest.parameter(CLIENT_ASSERTION_TYPE) == CLIENT_ASSERTION_JWT_BEARER
    }
}