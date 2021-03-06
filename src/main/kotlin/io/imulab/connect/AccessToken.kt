package io.imulab.connect

import io.imulab.connect.client.SigningAlgorithm
import io.imulab.connect.client.resolvePlainTextSecret
import kotlinx.coroutines.*
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.ErrorCodes
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.AesKey
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver
import java.nio.charset.StandardCharsets
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
     * If the token is not valid, an exception will be raised. Otherwise, the included claims are returned.
     */
    fun validateToken(token: String, request: Request): JwtClaims
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

    /**
     * Delete the token associated with certain request
     */
    suspend fun deleteByRequestId(requestId: String)
}

/**
 * Helper to combine operations of [AccessTokenStrategy] and [AccessTokenRepository] to allow
 * asynchronous operations where IO bound tasks are executed on IO threads.
 */
class AccessTokenHelper(
    private val lifespan: Duration,
    private val strategy: AccessTokenStrategy,
    private val repository: AccessTokenRepository
) {
    suspend fun issueToken(request: Request, response: Response): Job {
        val token = strategy.newToken(request)
        response.apply {
            setAccessToken(token)
            setTokenType()
            setExpiresIn(lifespan.toMillis() / 1000)
        }
        response.setAccessToken(token)
        return coroutineScope {
            launch(Dispatchers.IO) {
                request.session.savedByRequestId = request.id
                repository.save(token, request.session)
            }
        }
    }

    suspend fun deleteByRequestId(requestId: String): Job {
        return coroutineScope {
            launch(Dispatchers.IO) {
                repository.deleteByRequestId(requestId)
            }
        }
    }
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
        var keyId = ""
        val key = if (signingAlgorithm.symmetric) {
            AesKey(request.client.resolvePlainTextSecret().toByteArray(StandardCharsets.UTF_8))
        } else {
            val jwk = jwks.selectKeyForSignature(request.client.id, signingAlgorithm)
            keyId = jwk.keyId
            jwk.resolvePrivateKey()
        }

        return JsonWebSignature().also { jws ->
            if (keyId.isNotEmpty())
                jws.keyIdHeaderValue = keyId
            jws.algorithmHeaderValue = signingAlgorithm.value
            jws.key = key
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

    override fun validateToken(token: String, request: Request): JwtClaims {
        return try {
            JwtConsumerBuilder().apply {
                setRequireJwtId()
                setExpectedIssuer(issuerUrl)
                setSkipDefaultAudienceValidation()
                setRequireIssuedAt()
                setRequireExpirationTime()
                if (signingAlgorithm.symmetric)
                    setVerificationKey(
                        AesKey(request.client.resolvePlainTextSecret().toByteArray(StandardCharsets.UTF_8))
                    )
                else
                    setVerificationKeyResolver(JwksVerificationKeyResolver(jwks.jsonWebKeys))

            }.build().processToClaims(token)
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