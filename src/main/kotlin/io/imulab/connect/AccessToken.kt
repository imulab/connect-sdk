package io.imulab.connect

import io.imulab.connect.client.SigningAlgorithm
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.ErrorCodes
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.time.Duration

/**
 * Access token related algorithms.
 */
interface AccessTokenStrategy {
    /**
     * Derive the identifier for this token that is suitable to be used as the index
     * to store this access token. By default, it is the token itself.
     */
    fun computeIdentifier(token: String): String = token

    /**
     * Generate a new access token for the request.
     */
    fun newToken(request: Request): String

    /**
     * Validate the given access token with the information assist of the original session used to generate it.
     * If the token is not valid, an exception will be raised.
     */
    fun validateToken(token: String, session: Session)
}

/**
 * Repository for access token.
 */
interface AccessTokenRepository {
    /**
     * Get the session associated with [token].
     */
    suspend fun getSession(token: String): Session

    /**
     * Save the token and associate it with the session.
     */
    suspend fun save(token: String, session: Session)

    /**
     * Delete the token
     */
    suspend fun delete(token: String)
}

/**
 * Jwt based access token implementation of [AccessTokenStrategy].
 */
class JwtAccessTokenStrategy(
    private val signingAlgorithm: SigningAlgorithm,
    private val jwks: JsonWebKeySet,
    private val lifespan: Duration,
    private val issuerUrl: String
) : AccessTokenStrategy {

    override fun computeIdentifier(token: String): String {
        return try {
            JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .setRequireJwtId()
                .build()
                .processToClaims(token).jwtId
        } catch (e: Throwable) {
            throw invalidAccessToken()
        }
    }

    override fun newToken(request: Request): String {
        val key = jwks.selectKeyForSignature(request.client.id, signingAlgorithm)

        return JsonWebSignature().also { jws ->
            jws.keyIdHeaderValue = key.keyId
            jws.algorithmHeaderValue = key.algorithm
            jws.key = key.resolvePrivateKey()
            jws.payload = JwtClaims().also { c ->
                request.session.accessClaims.forEach { k, v -> c.setClaim(k, v) }
                c.setGeneratedJwtId()
                c.setIssuedAtToNow()
                c.setNotBeforeMinutesInThePast(0f)
                c.setExpirationTimeMinutesInTheFuture(lifespan.toMinutes().toFloat())
                c.issuer = issuerUrl
                c.subject = request.session.obfuscatedSubject
                c.setAudience(request.client.id)
                c.setScope(request.session.grantedScopes)
            }.toJson()
        }.compactSerialization
    }

    override fun validateToken(token: String, session: Session) {
        val key = jwks.selectKeyForSignature(session.clientId, signingAlgorithm)

        try {
            JwtConsumerBuilder()
                .setRequireJwtId()
                .setVerificationKey(key.resolvePublicKey())
                .setExpectedIssuer(issuerUrl)
                .setSkipDefaultAudienceValidation()
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .build()
                .process(token)
        } catch (e: InvalidJwtException) {
            when {
                e.errorDetails.any { it.errorCode == ErrorCodes.EXPIRED } ->
                    throw expiredAccessToken()
                else -> throw invalidAccessToken()
            }
        }
    }

    private fun invalidAccessToken(): ConnectException = Errors.invalidGrant("invalid access token")

    private fun expiredAccessToken(): ConnectException = Errors.invalidGrant("access token expired")
}