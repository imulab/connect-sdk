package io.imulab.connect.handler

import io.imulab.connect.*
import io.imulab.connect.client.GrantType
import io.imulab.connect.client.ResponseType
import io.imulab.connect.client.mustAcceptGrantType
import io.imulab.connect.client.mustAcceptResponseType
import kotlinx.coroutines.Job

/**
 * Handler responsible for hybrid flow. This implementation only handles the authorize leg of the flow. Since the
 * token leg of the flow is completely identical to that of the authorize code flow, to gain functionality of the
 * token leg, chain a [AuthorizeCodeFlowHandler] before or after this handler.
 */
class HybridFlowHandler(
    private val authorizeCodeHelper: AuthorizeCodeHelper,
    private val accessTokenHelper: AccessTokenHelper,
    private val idTokenHelper: IdTokenHelper
) : AuthorizeHandler {

    override suspend fun authorize(request: AuthorizeRequest, response: Response) {
        if (!supports(request))
            return

        val authorizeCodeJob = issueAuthorizeCode(request, response).also {
            it.invokeOnCompletion { request.markResponseTypeAsHandled(ResponseType.CODE) }
        }
        val accessTokenJob = issueAccessToken(request, response)?.also {
            it.invokeOnCompletion { request.markResponseTypeAsHandled(ResponseType.TOKEN) }
        }

        authorizeCodeJob.join()
        accessTokenJob?.join()

        issueIdToken(request, response)
        request.markResponseTypeAsHandled(ResponseType.ID_TOKEN)
    }

    private suspend fun issueAuthorizeCode(request: AuthorizeRequest, response: Response): Job {
        request.client.apply {
            mustAcceptResponseType(ResponseType.CODE)
        }
        return authorizeCodeHelper.issueCode(request, response)
    }

    private suspend fun issueAccessToken(request: AuthorizeRequest, response: Response): Job? {
        return if (request.responseTypes.contains(ResponseType.TOKEN)) {
            request.client.apply {
                mustAcceptResponseType(ResponseType.TOKEN)
                mustAcceptGrantType(GrantType.IMPLICIT)
            }
            accessTokenHelper.issueToken(request, response)
        } else null
    }

    private fun issueIdToken(request: AuthorizeRequest, response: Response) {
        if (request.responseTypes.contains(ResponseType.ID_TOKEN) && request.session.authorizeIdToken()) {
            request.client.apply {
                mustAcceptResponseType(ResponseType.ID_TOKEN)
            }
            idTokenHelper.issueToken(request, response)
        }
    }

    override fun supports(request: AuthorizeRequest): Boolean {
        return request.responseTypes.containsExactly(ResponseType.CODE, ResponseType.TOKEN) ||
            request.responseTypes.containsExactly(ResponseType.CODE, ResponseType.ID_TOKEN) ||
            request.responseTypes.containsExactly(ResponseType.CODE, ResponseType.TOKEN, ResponseType.ID_TOKEN)
    }
}
