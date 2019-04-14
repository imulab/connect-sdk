package io.imulab.connect.handler

import io.imulab.connect.*
import io.imulab.connect.client.*

/**
 * Handler responsible for implicit flow
 */
class ImplicitFlowHandler(
    private val accessTokenHelper: AccessTokenHelper,
    private val idTokenHelper: IdTokenHelper
) : AuthorizeHandler {

    override suspend fun authorize(request: AuthorizeRequest, response: Response) {
        if (!supports(request))
            return

        if (request.responseTypes.contains(ResponseType.TOKEN))
            issueAccessToken(request, response)

        if (request.responseTypes.contains(ResponseType.ID_TOKEN))
            issueIdToken(request, response)
    }

    private suspend fun issueAccessToken(request: AuthorizeRequest, response: Response) {
        try {
            request.client.apply {
                mustAcceptResponseType(ResponseType.TOKEN)
                mustAcceptGrantType(GrantType.IMPLICIT)
            }

            accessTokenHelper.issueToken(request, response).join()
        } finally {
            request.markResponseTypeAsHandled(ResponseType.TOKEN)
        }
    }

    private fun issueIdToken(request: AuthorizeRequest, response: Response) {
        try {
            if (!request.session.authorizeIdToken())
                return

            request.client.apply {
                mustAcceptResponseType(ResponseType.ID_TOKEN)
                mustAcceptGrantType(GrantType.IMPLICIT)
            }

            idTokenHelper.issueToken(request, response)
        } finally {
            request.markResponseTypeAsHandled(ResponseType.ID_TOKEN)
        }
    }

    override fun supports(request: AuthorizeRequest): Boolean {
        return request.responseTypes.containsExactly(ResponseType.TOKEN) ||
            request.responseTypes.containsExactly(ResponseType.ID_TOKEN) ||
            request.responseTypes.containsExactly(ResponseType.TOKEN, ResponseType.ID_TOKEN)
    }
}