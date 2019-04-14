package io.imulab.connect.auth

import io.imulab.connect.ConnectTokenRequest
import io.imulab.connect.Errors
import io.imulab.connect.TokenRequest
import io.imulab.connect.client.AuthenticationMethod
import io.imulab.connect.client.Client
import io.imulab.connect.client.ClientLookup
import io.imulab.connect.client.ClientSecretAware
import io.imulab.connect.spi.HttpRequest
import io.imulab.connect.spi.SecretComparator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import java.nio.charset.StandardCharsets
import java.util.*

private const val AUTH_HEADER = "Authorization"
private const val BASIC = "Basic"
private const val SPACE = " "
private const val COLON = ":"

/**
 * Authenticator to handle basic client authentication.
 */
class ClientSecretBasicAuthenticator(
    private val clientLookup: ClientLookup,
    private val secretComparator: SecretComparator
) : Authenticator {

    private val decoder = Base64.getDecoder()

    override suspend fun authenticate(httpRequest: HttpRequest, request: TokenRequest) {
        if (!supports(httpRequest))
            return
        else if (isClientSet(request))
            return

        val parts = decodeHeader(httpRequest)
        val client = findClient(parts[0])

        compareSecret(parts[1], client)

        request.mergeWith(ConnectTokenRequest(id = "", _client = client))
    }

    private fun decodeHeader(httpRequest: HttpRequest): List<String> {
        val raw = kotlin.runCatching {
            decoder.decode(
                httpRequest.header(AUTH_HEADER).removePrefix(BASIC + SPACE)
            ).toString(StandardCharsets.UTF_8)
        }.getOrElse { throw Errors.clientForbidden("unable to decode authorization header as base64") }

        val parts = raw.split(COLON)
        if (parts.size != 2)
            throw Errors.clientForbidden("malformed authorization header")

        return parts
    }

    private suspend fun findClient(id: String): Client {
        return kotlin.runCatching {
            runBlocking {
                async(Dispatchers.IO) { clientLookup.findById(id) }
            }.await()
        }.getOrElse {
            throw Errors.clientForbidden("unable to verify client identity")
        }.apply {
            if (tokenEndpointAuthMethod != AuthenticationMethod.BASIC)
                throw Errors.clientForbidden("client is not registered to use ${AuthenticationMethod.BASIC.value}")
        }
    }

    private fun compareSecret(plain: String, client: Client) {
        client as? ClientSecretAware
            ?: throw Errors.clientForbidden("unable to determine client secret")

        if (!secretComparator.compare(plain, client.secret))
            throw Errors.clientForbidden("incorrect client secret")
    }

    override fun implements(): List<AuthenticationMethod> = listOf(AuthenticationMethod.BASIC)

    override fun supports(httpRequest: HttpRequest): Boolean =
        httpRequest.header(AUTH_HEADER).startsWith(BASIC + SPACE)
}