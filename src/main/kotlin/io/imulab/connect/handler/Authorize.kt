package io.imulab.connect.handler

import io.imulab.connect.*
import io.imulab.connect.client.GrantType
import io.imulab.connect.client.ResponseType
import io.imulab.connect.client.mustAcceptGrantType
import io.imulab.connect.client.mustAcceptResponseType

/**
 * Handler responsible for authorization code flow.
 */
class AuthorizeCodeFlowHandler(
    private val authorizeCodeHelper: AuthorizeCodeHelper,
    private val accessTokenHelper: AccessTokenHelper,
    private val refreshTokenHelper: RefreshTokenHelper,
    private val idTokenHelper: IdTokenHelper
) : AuthorizeHandler, TokenHandler {

    override suspend fun authorize(request: AuthorizeRequest, response: Response) {
        if (!supports(request))
            return

        try {
            request.client.apply {
                mustAcceptResponseType(ResponseType.CODE)
            }

            authorizeCodeHelper.issueCode(request, response).join()
        } finally {
            request.markResponseTypeAsHandled(ResponseType.CODE)
        }
    }

    override fun supports(request: AuthorizeRequest): Boolean {
        return request.responseTypes.containsExactly(ResponseType.CODE)
    }

    override suspend fun updateSession(request: TokenRequest) {
        if (!supports(request))
            return

        try {
            request.client.mustAcceptGrantType(GrantType.CODE)

            val authorizeSession = authorizeCodeHelper.reviveSession(request.code).apply {
                when {
                    clientId != request.client.id ->
                        throw Errors.invalidGrant("authorization code was issued to a different client")
                    finalRedirectUri != request.redirectUri ->
                        throw Errors.invalidGrant("authorization code was issued to a different uri")
                }
            }

            request.session.replacedWith(authorizeSession)
        } finally {
            authorizeCodeHelper.deleteCode(request.code)
        }
    }

    override suspend fun issueToken(request: TokenRequest, response: Response) {
        if (!supports(request))
            return

        val accessTokenJob = accessTokenHelper.issueToken(request, response)

        val refreshTokenJob = if (request.session.authorizedRefreshToken())
            refreshTokenHelper.issueToken(request, response)
        else
            null

        accessTokenJob.join()
        refreshTokenJob?.join()

        if (request.session.authorizeIdToken())
            idTokenHelper.issueToken(request, response)
    }

    override fun supports(request: TokenRequest): Boolean {
        return request.grantTypes.containsExactly(GrantType.CODE)
    }
}
