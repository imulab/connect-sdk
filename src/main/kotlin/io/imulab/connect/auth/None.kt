package io.imulab.connect.auth

import io.imulab.connect.ConnectTokenRequest
import io.imulab.connect.Errors
import io.imulab.connect.TokenRequest
import io.imulab.connect.client.AuthenticationMethod
import io.imulab.connect.client.ClientLookup
import io.imulab.connect.client.ClientType
import io.imulab.connect.spi.HttpRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking

/**
 * Authenticator implementation to handle the 'none' method edge case.
 */
class NoneAuthenticator(
    private val clientLookup: ClientLookup
) : Authenticator {

    override suspend fun authenticate(httpRequest: HttpRequest, request: TokenRequest) {
        if (isClientSet(request))
            return

        val clientId = httpRequest.parameter(CLIENT_ID)
        if (clientId.isEmpty())
            throw Errors.clientForbidden("cannot resolve client_id")

        val client = kotlin.runCatching {
            runBlocking {
                async(Dispatchers.IO) { clientLookup.findById(clientId) }
            }.await()
        }.getOrElse {
            throw Errors.clientForbidden("unable to verify client identity")
        }.apply {
            if (type != ClientType.PUBLIC)
                throw Errors.clientForbidden("non-public client cannot skip authentication")
            if (tokenEndpointAuthMethod != AuthenticationMethod.NONE)
                throw Errors.clientForbidden("client is not registered to use JWT based authentication")
        }

        request.mergeWith(ConnectTokenRequest(id = "", client = client))
    }

    override fun implements(): List<AuthenticationMethod> = listOf(AuthenticationMethod.NONE)

    // we do not support chained authentication in this case
    // have to explicitly call this authenticator.
    override suspend fun supports(httpRequest: HttpRequest): Boolean = false
}