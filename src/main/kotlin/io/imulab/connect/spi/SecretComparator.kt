package io.imulab.connect.spi

/**
 * Service provider interface to compare a plain text secret against a certain version of that secret.
 */
interface SecretComparator {

    /**
     * Returns true if [plain] secret can be considered equal to [truth] version of secret.
     */
    fun compare(plain: String, truth: String): Boolean
}