package io.imulab.connect.handler

import io.imulab.connect.*
import io.imulab.connect.client.GrantType
import io.imulab.connect.client.mustAcceptGrantType

class RefreshFlowHandler(
    private val accessTokenHelper: AccessTokenHelper,
    private val refreshTokenHelper: RefreshTokenHelper,
    private val idTokenHelper: IdTokenHelper
) : TokenHandler {

    override suspend fun updateSession(request: TokenRequest) {
        if (!supports(request))
            return

        try {
            request.client.mustAcceptGrantType(GrantType.REFRESH)
            val lastSession = refreshTokenHelper.reviveSession(request.refreshToken).apply {
                when {
                    clientId != request.client.id ->
                        throw Errors.invalidGrant("authorization code was issued to a different client")
                    finalRedirectUri != request.redirectUri ->
                        throw Errors.invalidGrant("authorization code was issued to a different uri")
                }

            }
            request.session.replacedWith(lastSession)
        } finally {
            accessTokenHelper.deleteByRequestId(request.session.savedByRequestId)
            refreshTokenHelper.deleteByRequestId(request.session.savedByRequestId)
        }
    }

    override suspend fun issueToken(request: TokenRequest, response: Response) {
        if (!supports(request))
            return

        val accessTokenJob = accessTokenHelper.issueToken(request, response)
        val refreshTokenJob = if (request.session.authorizedRefreshToken())
            refreshTokenHelper.issueToken(request, response)
        else null

        accessTokenJob.join()
        refreshTokenJob?.join()

        if (request.session.authorizeIdToken())
            idTokenHelper.issueToken(request, response)
    }

    override fun supports(request: TokenRequest): Boolean {
        return request.grantTypes.containsExactly(GrantType.REFRESH)
    }
}