package io.imulab.connect

import io.imulab.connect.client.SigningAlgorithm
import kotlinx.coroutines.*
import org.jose4j.jca.ProviderContext
import org.jose4j.jws.HmacUsingShaAlgorithm
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.MessageDigest
import java.util.*
import java.util.concurrent.ThreadLocalRandom

/**
 * Standard scope to grant refresh token
 */
const val offlineAccess = "offline_access"

/**
 * Refresh token related algorithms.
 */
interface RefreshTokenStrategy {
    /**
     * Derive the identifier for this token that is suitable to be used as the index
     * to store this refresh token. By default, it is the token itself.
     */
    fun computeIdentifier(token: String): String = token

    /**
     * Generate a new refresh token for the token request.
     */
    fun newToken(request: TokenRequest): String

    /**
     * Validate the given refresh token with the information assist of the original session used to generate it.
     * If the token is not valid, an exception will be raised.
     */
    fun validateToken(token: String, session: Session)
}

/**
 * Repository for refresh token.
 */
interface RefreshTokenRepository {
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
 * Helper to combine operations of [RefreshTokenStrategy] and [RefreshTokenRepository] to allow
 * asynchronous operations where IO bound tasks are executed on IO threads.
 */
class RefreshTokenHelper(
    private val strategy: RefreshTokenStrategy,
    private val repository: RefreshTokenRepository
) {
    suspend fun issueToken(request: TokenRequest, response: Response): Job {
        val token = strategy.newToken(request)
        response.setRefreshToken(token)
        return runBlocking {
            launch(Dispatchers.IO) {
                request.session.savedByRequestId = request.id
                repository.save(token, request.session)
            }
        }
    }

    suspend fun reviveSession(token: String): Session {
        return runBlocking {
            async(Dispatchers.IO) {
                repository.getSession(token)
            }
        }.await().also {
            strategy.validateToken(token, it)
        }
    }

    suspend fun deleteByRequestId(requestId: String): Job {
        return runBlocking {
            launch(Dispatchers.IO) {
                repository.deleteByRequestId(requestId)
            }
        }
    }
}

/**
 * HMAC-SHA2 based implementation of [RefreshTokenStrategy].
 */
class HmacRefreshTokenStrategy(
    signingAlgorithm: SigningAlgorithm,
    private val key: Key,
    private val entropy: Int = 32
) : RefreshTokenStrategy {

    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()
    private val hmac: HmacUsingShaAlgorithm = when (signingAlgorithm) {
        SigningAlgorithm.HS256 -> HmacUsingShaAlgorithm.HmacSha256()
        SigningAlgorithm.HS384 -> HmacUsingShaAlgorithm.HmacSha384()
        SigningAlgorithm.HS512 -> HmacUsingShaAlgorithm.HmacSha512()
        else -> throw UnsupportedOperationException("$signingAlgorithm is unsupported.")
    }

    /**
     * The identifier is calculated as the SHA-256 hash of the entire token.
     */
    override fun computeIdentifier(token: String): String {
        val messageDigest = MessageDigest.getInstance("SHA-256")
        return messageDigest.digest(token.toByteArray(StandardCharsets.UTF_8)).toString(StandardCharsets.UTF_8)
    }

    /**
     * Token is generated as `base64(<random bytes>).base64(<signature of random bytes>)`.
     */
    override fun newToken(request: TokenRequest): String {
        val randomBytes = ByteArray(entropy).apply {
            ThreadLocalRandom.current().nextBytes(this)
        }
        val signatureBytes = hmac.sign(key, randomBytes, ProviderContext())
        return encoder.encodeToString(randomBytes) + "." + encoder.encodeToString(signatureBytes)
    }

    override fun validateToken(token: String, session: Session) {
        val parts = token.split(".")
        if (parts.size != 2) {
            throw invalidRefreshToken()
        }

        if (!hmac.verifySignature(
                decoder.decode(parts[1]),
                key,
                decoder.decode(parts[0]),
                ProviderContext())) {
            throw invalidRefreshToken()
        }
    }

    private fun invalidRefreshToken(): ConnectException = Errors.invalidGrant("invalid refresh token")
}