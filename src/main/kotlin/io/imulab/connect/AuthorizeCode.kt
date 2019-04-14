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
 * Authorization code related algorithms.
 */
interface AuthorizeCodeStrategy {
    /**
     * Derive the identifier for this code that is suitable to be used as the index
     * to store this authorization code. By default, it is the code itself.
     */
    fun computeIdentifier(code: String): String = code

    /**
     * Generate a new authorization code for the request.
     */
    fun newCode(request: AuthorizeRequest): String

    /**
     * Validate the given authorization code with the information assist of the original session used to generate it.
     * If the code is not valid, an exception will be raised.
     */
    fun validateCode(code: String, session: Session)
}

/**
 * Repository for authorization code
 */
interface AuthorizeCodeRepository {
    /**
     * Get the session associated with [code].
     */
    suspend fun getSession(code: String): Session

    /**
     * Save the code and associate it with the session.
     */
    suspend fun save(code: String, session: Session)

    /**
     * Delete the code
     */
    suspend fun delete(code: String)
}

/**
 * Helper to combine operations of [AuthorizeCodeStrategy] and [AuthorizeCodeRepository] to allow
 * asynchronous operations where IO bound tasks are executed on IO threads.
 */
class AuthorizeCodeHelper(
    private val strategy: AuthorizeCodeStrategy,
    private val repository: AuthorizeCodeRepository
) {
    suspend fun reviveSession(code: String): Session {
        return runBlocking {
            async(Dispatchers.IO) {
                repository.getSession(code)
            }
        }.await().also {
            strategy.validateCode(code, it)
        }
    }

    suspend fun issueCode(request: AuthorizeRequest, response: Response): Job {
        val code = strategy.newCode(request)
        response.setCode(code)
        return runBlocking {
            launch(Dispatchers.IO) {
                request.session.savedByRequestId = request.id
                repository.save(code, request.session)
            }
        }
    }

    suspend fun deleteCode(code: String): Job {
        return runBlocking {
            launch(Dispatchers.IO) {
                repository.delete(code)
            }
        }
    }
}

/**
 * HMAC-SHA2 based implementation of [AuthorizeCodeStrategy].
 */
class HmacAuthorizeCodeStrategy(
    signingAlgorithm: SigningAlgorithm,
    private val key: Key,
    private val entropy: Int = 32
) : AuthorizeCodeStrategy {

    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()
    private val hmac: HmacUsingShaAlgorithm = when (signingAlgorithm) {
        SigningAlgorithm.HS256 -> HmacUsingShaAlgorithm.HmacSha256()
        SigningAlgorithm.HS384 -> HmacUsingShaAlgorithm.HmacSha384()
        SigningAlgorithm.HS512 -> HmacUsingShaAlgorithm.HmacSha512()
        else -> throw UnsupportedOperationException("$signingAlgorithm is unsupported.")
    }

    /**
     * The identifier is calculated as the SHA-256 hash of the entire code.
     */
    override fun computeIdentifier(code: String): String {
        val messageDigest = MessageDigest.getInstance("SHA-256")
        return messageDigest.digest(code.toByteArray(StandardCharsets.UTF_8)).toString(StandardCharsets.UTF_8)
    }

    /**
     * Code is generated as `base64(<random bytes>).base64(<signature of random bytes>)`.
     */
    override fun newCode(request: AuthorizeRequest): String {
        val randomBytes = ByteArray(entropy).apply {
            ThreadLocalRandom.current().nextBytes(this)
        }
        val signatureBytes = hmac.sign(key, randomBytes, ProviderContext())
        return encoder.encodeToString(randomBytes) + "." + encoder.encodeToString(signatureBytes)
    }

    override fun validateCode(code: String, session: Session) {
        val parts = code.split(".")
        if (parts.size != 2) {
            throw invalidAuthorizationCode()
        }

        if (!hmac.verifySignature(
                decoder.decode(parts[1]),
                key,
                decoder.decode(parts[0]),
                ProviderContext())) {
            throw invalidAuthorizationCode()
        }
    }

    private fun invalidAuthorizationCode(): ConnectException = Errors.invalidGrant("invalid authorization code")
}