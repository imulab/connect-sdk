package io.imulab.connect.handler

import io.imulab.connect.*
import io.imulab.connect.client.ClientType
import io.imulab.connect.client.GrantType
import io.imulab.connect.client.mustAcceptAllScopes
import io.imulab.connect.client.mustAcceptGrantType

class ClientCredentialsFlowHandler(
    private val accessTokenHelper: AccessTokenHelper,
    private val refreshTokenHelper: RefreshTokenHelper
) : TokenHandler {

    override suspend fun updateSession(request: TokenRequest) {
        if (!supports(request))
            return

        request.client.apply {
            if (type != ClientType.PUBLIC)
                throw Errors.invalidGrant("public client cannot use client_credentials grant")
            mustAcceptGrantType(GrantType.CLIENT)
            mustAcceptAllScopes(request.scopes)
        }

        request.session.grantedScopes.addAll(request.scopes)
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
    }

    override fun supports(request: TokenRequest): Boolean {
        return request.grantTypes.containsExactly(GrantType.CLIENT)
    }
}