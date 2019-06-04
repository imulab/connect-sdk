package io.imulab.connect.spi

import io.imulab.connect.*
import io.imulab.connect.client.Client
import org.jose4j.jwt.JwtClaims
import java.time.LocalDateTime

/**
 * Interfaces to implement in order to receive protection as an OAuth resource.
 */
interface OAuthResource {

    /**
     * Strategy to verify the access token.
     */
    val accessTokenStrategy: AccessTokenStrategy

    /**
     * The requested set of scopes that must have been granted to access this resource.
     */
    val requiredScopes: Set<String>

    /**
     * The scope comparator. By default, does string equality comparison
     */
    val scopeComparator: (String, String) -> Boolean
        get() = { a, b -> a == b }

    /**
     * Main entry point to protect this resource.
     *
     * By default, this method expects a "Bearer" token in the "Authorization" header, and will use [accessTokenStrategy]
     * to validate it. The [AccessTokenStrategy.validateToken] method will be called with an empty request. This request
     * will throw [NotImplementedError] if any of its method or properties are invoked.
     *
     * If it is needed to supply information to [accessTokenStrategy] via the request, users can override this method.
     *
     * If token is invalid, an invalid_grant error will be raised. If one ore more scope is missing, an access_denied
     * error will be raised.
     *
     * This method eventually returns a decoded [JwtClaims] for the caller, in case further processing is desired.
     */
    suspend fun protected(request: HttpRequest): JwtClaims {
        try {
            val accessToken = request.header("Authorization").removePrefix("Bearer").trim()
            if (accessToken.isEmpty())
                throw Errors.invalidGrant("missing access token.")

            val claims = accessTokenStrategy.validateToken(accessToken, NothingRequest)

            if (requiredScopes.any { required ->
                claims.getScopes().none { supplied -> scopeComparator(supplied, required) }
            }) {
                throw Errors.accessDenied("missing required scope.")
            }

            return claims
        } catch (t: Throwable) {
            if (t is ConnectException)
                throw t
            throw Errors.invalidGrant("unable to verify access token: ${t.message}")
        }
    }

    private object NothingRequest : Request {
        override val id: String
            get() = shouldNotCall()
        override val requestedAt: LocalDateTime
            get() = shouldNotCall()
        override val client: Client
            get() = shouldNotCall()
        override val redirectUri: String
            get() = shouldNotCall()
        override val scopes: Set<String>
            get() = shouldNotCall()
        override val session: Session
            get() = shouldNotCall()
        override val rawValues: Map<String, String>
            get() = shouldNotCall()

        private fun shouldNotCall(): Nothing = throw NotImplementedError("should not call.")
    }
}