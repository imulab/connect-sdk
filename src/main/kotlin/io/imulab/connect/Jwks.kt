package io.imulab.connect

import io.imulab.connect.client.EncryptionAlgorithm
import io.imulab.connect.client.SigningAlgorithm
import org.jose4j.jwk.*
import java.security.Key

fun JsonWebKey.resolvePrivateKey(): Key = when(this) {
    is RsaJsonWebKey -> this.rsaPrivateKey
    is EllipticCurveJsonWebKey -> this.ecPrivateKey
    is PublicJsonWebKey -> this.privateKey
    is OctetSequenceJsonWebKey -> this.key
    else -> this.key
}

fun JsonWebKey.resolvePublicKey(): Key = when (this) {
    is RsaJsonWebKey -> this.getRsaPublicKey()
    is EllipticCurveJsonWebKey -> this.ecPublicKey
    is PublicJsonWebKey -> this.publicKey
    is OctetSequenceJsonWebKey -> this.key
    else -> this.key
}

/**
 * Returns a json web key that is used for signing and matches the [signingAlgorithm].
 *
 * If no keys were found, throws exception. If exactly one key was found, returns that key. If multiple keys were
 * found, a key whose index is the remainder of the sum of ascii characters of the client's id against the size of
 * the candidates. This ensure that when multiple keys are qualified, different clients have a chance to be signed
 * with different keys, but a single client is always signed with the same key, assuming the ordering from
 * [JsonWebKeySet.findJsonWebKeys] is stable.
 */
fun JsonWebKeySet.selectKeyForSignature(clientId: String, signingAlgorithm: SigningAlgorithm): JsonWebKey {
    val keys = findJsonWebKeys(null, null, Use.SIGNATURE, signingAlgorithm.value)
    return when (keys.size) {
        0 -> throw Errors.serverError("server unable to locate signing key with algorithm ${signingAlgorithm.value}")
        1 -> keys[0]
        else -> {
            val sum = clientId.map { c -> c.toInt() }.reduce { acc, i -> acc + i }
            keys[sum % keys.size]
        }
    }
}

/**
 * Returns a json web key that is used for encryption and matches the [encryptionAlgorithm]. If no keys were found,
 * an exception is thrown.
 */
fun JsonWebKeySet.selectKeyForEncryption(encryptionAlgorithm: EncryptionAlgorithm): JsonWebKey {
    return findJsonWebKey(null, null, Use.ENCRYPTION, encryptionAlgorithm.value) ?:
        throw Errors.serverError("unable to locate encryption key with algorithm ${encryptionAlgorithm.value}")
}