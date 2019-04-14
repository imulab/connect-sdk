package io.imulab.connect

import io.imulab.connect.client.*
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.keys.AesKey
import java.nio.charset.StandardCharsets
import java.time.Duration

/**
 * Id token related algorithm.
 */
interface IdTokenStrategy {
    /**
     * Generate a new id token.
     */
    fun newToken(request: Request): String
}

/**
 * JWT + JWE based implementation of id token strategy.
 */
class JwxIdTokenStrategy(
    private val lifespan: Duration,
    private val issuerUrl: String,
    private val jwks: JsonWebKeySet,
    private val signingAlgorithm: SigningAlgorithm
) : IdTokenStrategy {

    override fun newToken(request: Request): String {
        val claims = createClaims(request)
        val signed = doSign(claims, request.client)

        if (!request.client.requireIdTokenEncryption())
            return signed

        val clientJwks = request.client.resolveJwks()   // this could be a slow call
        return doEncrypt(signed, request.client, clientJwks)
    }

    private fun createClaims(request: Request): JwtClaims {
        return JwtClaims().also { c ->
            request.session.idClaims.forEach { k, v -> c.setClaim(k, v) }
            c.setGeneratedJwtId()
            c.setIssuedAtToNow()
            c.setExpirationTimeMinutesInTheFuture(lifespan.toMinutes().toFloat())
            c.setNotBeforeMinutesInThePast(0f)
            c.issuer = issuerUrl
            c.setAudience(request.client.id)
            c.subject = request.session.obfuscatedSubject
            if (request.session.authTime != null)
                c.setAuthTime(request.session.authTime!!)
            if (request.session.nonce.isNotEmpty())
                c.setNonce(request.session.nonce)
            if (request.session.acrValues.isNotEmpty())
                c.setAcrValues(request.session.acrValues)
        }
    }

    private fun doSign(claims: JwtClaims, client: Client): String {
        val jws = JsonWebSignature().also { jws ->
            jws.algorithmHeaderValue = client.idTokenSignedResponseAlgorithm.value
            jws.payload = claims.toJson()
        }

        when (client.idTokenSignedResponseAlgorithm) {
            SigningAlgorithm.HS256,
            SigningAlgorithm.HS384,
            SigningAlgorithm.HS512 -> {
                if (client !is ClientSecretAware)
                    throw Errors.serverError("cannot resolve client secret to be used as signing key")
                jws.key = AesKey(client.plainTextSecret().toByteArray(StandardCharsets.UTF_8))
            }
            SigningAlgorithm.RS256,
            SigningAlgorithm.RS384,
            SigningAlgorithm.RS512,
            SigningAlgorithm.ES256,
            SigningAlgorithm.ES384,
            SigningAlgorithm.ES512,
            SigningAlgorithm.PS256,
            SigningAlgorithm.PS384,
            SigningAlgorithm.PS512 -> {
                val key = jwks.selectKeyForSignature(client.id, signingAlgorithm)
                jws.key = key.resolvePrivateKey()
                jws.keyIdHeaderValue = key.keyId
            }
            SigningAlgorithm.NONE -> jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE)
        }

        return jws.compactSerialization
    }

    private fun doEncrypt(raw: String, client: Client, clientJwks: JsonWebKeySet): String {
        return JsonWebEncryption().also { jwe ->
            jwe.setPlaintext(raw)
            jwe.contentTypeHeaderValue = "JWT"
            jwe.algorithmHeaderValue = client.idTokenEncryptedResponseAlgorithm.value
            jwe.encryptionMethodHeaderParameter = client.idTokenEncryptedResponseEncoding.value
            jwe.key = clientJwks.selectKeyForEncryption(client.idTokenEncryptedResponseAlgorithm).resolvePublicKey()
        }.compactSerialization
    }
}