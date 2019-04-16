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

private const val CONTENT_TYPE_HEADER = "Content-Type"
private const val FORM_URL_ENCODED = "application/x-www-form-urlencoded"
private const val CLIENT_SECRET = "client_secret"

/**
 * Authenticator to handle post client authentication.
 */
class ClientSecretPostAuthenticator(
    private val clientLookup: ClientLookup,
    private val secretComparator: SecretComparator = object : SecretComparator {
        override fun compare(plain: String, truth: String): Boolean = plain == truth
    }
) : Authenticator {

    override suspend fun authenticate(httpRequest: HttpRequest, request: TokenRequest) {
        if (!supports(httpRequest))
            return
        else if (isClientSet(request))
            return

        val client = findClient(httpRequest.parameter(CLIENT_ID))

        compareSecret(httpRequest.parameter(CLIENT_SECRET), client)

        request.mergeWith(ConnectTokenRequest(id = "", _client = client))
    }

    private suspend fun findClient(id: String): Client {
        return kotlin.runCatching {
            runBlocking {
                async(Dispatchers.IO) { clientLookup.findById(id) }
            }.await()
        }.getOrElse {
            throw Errors.clientForbidden("unable to verify client identity")
        }.apply {
            if (tokenEndpointAuthMethod != AuthenticationMethod.POST)
                throw Errors.clientForbidden("client is not registered to use ${AuthenticationMethod.POST.value}")
        }
    }

    private fun compareSecret(plain: String, client: Client) {
        client as? ClientSecretAware
            ?: throw Errors.clientForbidden("unable to determine client secret")

        if (!secretComparator.compare(plain, client.secret))
            throw Errors.clientForbidden("incorrect client secret")
    }

    override fun implements(): List<AuthenticationMethod> = listOf(AuthenticationMethod.POST)

    override fun supports(httpRequest: HttpRequest): Boolean {
        return httpRequest.method() == POST &&
            httpRequest.header(CONTENT_TYPE_HEADER) == FORM_URL_ENCODED &&
            httpRequest.parameter(CLIENT_ID).isNotEmpty() &&
            httpRequest.parameter(CLIENT_SECRET).isNotEmpty()
    }
}