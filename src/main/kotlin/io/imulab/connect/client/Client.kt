package io.imulab.connect.client

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import org.jose4j.jws.AlgorithmIdentifiers

/**
 * Primary interface for an Open ID Connect 1.0 client.
 *
 * @since inception
 */
interface Client {
    /**
     * Returns identifier of the client. The identifier needs to be globally unique.
     */
    fun id(): String

    /**
     * Returns the name of the client. Implementations are encouraged to assign a default
     * name to client if none is provided by the user. However, an empty string is permitted.
     */
    fun name(): String

    /**
     * Returns the type of the client. Defaults to [ClientType.CONFIDENTIAL] if user didn't
     * explicitly specify.
     */
    fun type(): ClientType

    /**
     * Returns the registered redirect uris. Client must register at least one redirect uri.
     */
    fun redirectUris(): Set<String>

    /**
     * Returns the registered response types. This will be affected by the supported_response_types
     * option defined in Open ID Connect 1.0 Discovery configuration.
     */
    fun responseTypes(): Set<ResponseType>

    /**
     * Returns the registered grant types. This will be affected by the supported_grant_types
     * option defined in Open ID Connect 1.0 Discovery configuration.
     */
    fun grantTypes(): Set<GrantType>

    /**
     * Returns the registered scopes. Requests made by the client must provide scopes that is acceptable
     * by the list of scopes registered here in order to be processed. However, the notion of acceptable
     * is not limited to string equality comparison, and is subject to implementation.
     */
    fun scopes(): Set<String>

    /**
     * Returns the application type of the client. The value defaults to [ApplicationType.WEB] if client
     * didn't explicitly register a value.
     */
    fun applicationType(): ApplicationType

    /**
     * Returns the registered list of email contacts.
     *
     * In principal, the values are unique and hence should be modelled using [Set]. However, to improve
     * ease of use of the API, we are using [List] here. This is usually not a huge issue as this field
     * is informational only.
     */
    fun contacts(): List<String>

    /**
     * Returns the logo uri of the client. An empty string indicates no uri registered.
     */
    fun logoUri(): String

    /**
     * Returns the client uri. An empty string indicates no uri registered.
     */
    fun clientUri(): String

    /**
     * Returns the policy uri of the client. An empty string indicates no uri registered.
     */
    fun policyUri(): String

    /**
     * Returns the terms of service uri of the client. An empty string indicates no uri registered.
     */
    fun tosUri(): String

    /**
     * Returns the json web key set uri of the client. An empty string indicates no uri registered.
     *
     * This field is mutually exclusive with [jwks]. Only one of [jwks] or [jwksUri] may be provided.
     */
    fun jwksUri(): String

    /**
     * Returns the raw json web key set value registered by the client. An empty string indicates client
     * did not register any raw value of json web key set.
     *
     * This field is mutually exclusive with [jwksUri]. Only one of [jwks] or [jwksUri] may be provided.
     */
    fun jwks(): String

    /**
     * Returns the sector identifier uri of the client. Only URL with HTTPS scheme is acceptable.
     * This uri is used to validate [redirectUris] and conduct pairwise pseudonymous subject value
     * calculation. An empty string indicates no uri was registered.
     */
    fun sectorIdentifierUri(): String

    /**
     * Returns the subject type of the user. This value is used to determine the algorithm during the
     * pseudonymous subject value calculation. The value defaults to [SubjectType.PUBLIC] is user did
     * not explicitly register.
     */
    fun subjectType(): SubjectType

    /**
     * Returns the JWS algorithm used to sign the id_token response. The value should default to
     * [SigningAlgorithm.RS256] if user did not explicitly specify.
     */
    fun idTokenSignedResponseAlgorithm(): SigningAlgorithm

    /**
     * Returns the JWS algorithm to negotiate the encryption key for JWE. The value should default to
     * [EncryptionAlgorithm.NONE] if user did not explicitly specify.
     *
     * This field has a negative XOR relation with [idTokenEncryptedResponseEncoding]. If value is not
     * equal to [EncryptionAlgorithm.NONE], the value of [idTokenEncryptedResponseEncoding] cannot equal
     * to [EncryptionEncoding.NONE] either.
     */
    fun idTokenEncryptedResponseAlgorithm(): EncryptionAlgorithm

    /**
     * Returns the JWS algorithm to encode the content for JWE. The value should default to
     * [EncryptionEncoding.NONE] if user did not explicitly specify.
     *
     * This field has a negative XOR relation with [idTokenEncryptedResponseAlgorithm]. If value is not
     * equal to [EncryptionEncoding.NONE], the value of [idTokenEncryptedResponseAlgorithm] cannot equal
     *  to [EncryptionAlgorithm.NONE] either.
     */
    fun idTokenEncryptedResponseEncoding(): EncryptionEncoding

    /**
     * Returns the JWS algorithm client will use to sign the request object. The value should default to
     * [SigningAlgorithm.RS256] if user did not explicitly specify.
     */
    fun requestObjectSigningAlgorithm(): SigningAlgorithm

    /**
     * Returns the JWS algorithm client uses to negotiate the encryption key for JWE request object. If not
     * specified, should default to [EncryptionAlgorithm.NONE].
     *
     * This field has a negative XOR relation with [requestObjectEncryptionEncoding]. If value is not
     * equal to [EncryptionAlgorithm.NONE], the value of [requestObjectEncryptionEncoding] cannot equal
     * to [EncryptionEncoding.NONE] either.
     */
    fun requestObjectEncryptionAlgorithm(): EncryptionAlgorithm

    /**
     * Returns the JWS algorithm client uses to encode the content for JWE request object. If not specified,
     * should default to [EncryptionEncoding.NONE].
     *
     * This field has a negative XOR relation with [requestObjectEncryptionAlgorithm]. If value is not
     * equal to [EncryptionEncoding.NONE], the value of [requestObjectEncryptionAlgorithm] cannot equal
     * to [EncryptionAlgorithm.NONE] either.
     */
    fun requestObjectEncryptionEncoding(): EncryptionEncoding

    /**
     * Returns the signing algorithm used to sign the user info endpoint response. If not specified, should default
     * to [SigningAlgorithm.NONE], which means the endpoint will return content in application/json format.
     */
    fun userInfoSignedResponseAlgorithm(): SigningAlgorithm

    /**
     * Returns the JWS algorithm to negotiate the encryption key for the JWE user info response. If not specified,
     * should default to [EncryptionAlgorithm.NONE].
     *
     * This field has a negative XOR relation with [userInfoEncryptedResponseEncoding]. If value is not
     * equal to [EncryptionAlgorithm.NONE], the value of [userInfoEncryptedResponseEncoding] cannot equal
     * to [EncryptionEncoding.NONE] either.
     */
    fun userInfoEncryptedResponseAlgorithm(): EncryptionAlgorithm

    /**
     * Returns the JWS algorithm to encode the JWE user info response content. If not specified, should default to
     * [EncryptionEncoding.NONE].
     *
     * This field has a negative XOR relation with [userInfoEncryptedResponseAlgorithm]. If value is not
     * equal to [EncryptionEncoding.NONE], the value of [userInfoEncryptedResponseAlgorithm] cannot equal
     * to [EncryptionAlgorithm.NONE] either.
     */
    fun userInfoEncryptedResponseEncoding(): EncryptionEncoding

    /**
     * Returns the authentication method employed by the token endpoint. If not specified, defaults to
     * [AuthenticationMethod.BASIC].
     */
    fun tokenEndpointAuthMethod(): AuthenticationMethod

    /**
     * Returns the algorithm used to sign the authentication JWT used at the token endpoint. This value is only used
     * when [tokenEndpointAuthMethod] is [AuthenticationMethod.JWT_PRIVATE] or [AuthenticationMethod.JWT_SECRET].
     *
     * When [tokenEndpointAuthMethod] is [AuthenticationMethod.BASIC], [AuthenticationMethod.POST], or
     * [AuthenticationMethod.NONE], this value can default to [SigningAlgorithm.NONE]. Otherwise, client must specify
     * a not-[SigningAlgorithm.NONE] value for this field.
     */
    fun tokenEndpointAuthSigningAlgorithm(): SigningAlgorithm

    /**
     * Returns the default max age specified by the client. If this value is greater than zero, user authentication
     * session will be imposed an expiry constraint specified by the number of seconds in this value.
     *
     * The max age value cannot be less than zero, which means ideally we should model it using unsigned data type.
     * However, since unsigned long is still experimental in Kotlin at the time of writing. We will just use long as
     * its data type and do extra validation.
     */
    fun defaultMaxAge(): Long

    /**
     * Returns whether auth_time claim is required.
     */
    fun requireAuthTime(): Boolean

    /**
     * Returns a list of default authentication class reference values.
     */
    fun defaultAcrValues(): List<String>

    /**
     * Returns a list of uris, each pointing to a file that contains a request object. Upon client registration, server
     * can read from these uris and cache its content. Each uri can optionally contain a fragment calculated by hashing
     * the content with SHA-256. If such fragment is present, server will also perform hash checks on the data received.
     */
    fun requestUris(): Set<String>
}

/**
 * Interface for obtaining the client's secret, in any form. This is intentionally separated with the main [Client]
 * interface to give implementation a choice to not expose secret.
 *
 * @since inception
 */
interface ClientSecretAware {
    /**
     * Returns client secret in the form of choice (e.g. plain text, hashed, or encrypted)
     */
    fun secret(): String
}

/**
 * Interface for obtaining the client's cached json web key set. Implementing this interface will help avoid request
 * time key set resolution, which impacts response time. This is intentionally separated with the main [Client]
 * interface to give choice to implementation.
 *
 * @since inception
 */
interface JwksCacheAware {
    /**
     * Returns the json web key set cached by the client.
     */
    fun jwksCache(): String
}

/**
 * Interface for obtaining the client's cached request object. Implementing this interface will help avoid request
 * time request object resolution, which impacts response time. This is intentionally separated with the main [Client]
 * interface to give choice to implementation.
 *
 * @since inception
 */
interface RequestCacheAware {
    /**
     * Returns the cached request object corresponding to the [requestUri]. If no such cache exists, an empty string
     * is returned instead.
     */
    fun uriForRequestCache(requestUri: String): String
}

enum class ClientType(val value: String) {
    PUBLIC("public"), CONFIDENTIAL("confidential")
}

enum class ResponseType(val value: String) {
    CODE("code"), TOKEN("token"), ID_TOKEN("id_token")
}

enum class GrantType(val value: String) {
    CODE("authorization_code"), IMPLICIT("implicit"),
    CLIENT("client_credentials"), PWD("password"), REFRESH("refresh_token")
}

enum class ApplicationType(val value: String) {
    WEB("web"), NATIVE("native")
}

enum class SubjectType(val value: String) {
    PUBLIC("public"), PAIRWISE("pairwise")
}

enum class SigningAlgorithm(val value: String) {
    HS256(AlgorithmIdentifiers.HMAC_SHA256),
    HS384(AlgorithmIdentifiers.HMAC_SHA384),
    HS512(AlgorithmIdentifiers.HMAC_SHA512),
    RS256(AlgorithmIdentifiers.RSA_USING_SHA256),
    RS384(AlgorithmIdentifiers.RSA_USING_SHA384),
    RS512(AlgorithmIdentifiers.RSA_USING_SHA384),
    ES256(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256),
    ES384(AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384),
    ES512(AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512),
    PS256(AlgorithmIdentifiers.RSA_PSS_USING_SHA256),
    PS384(AlgorithmIdentifiers.RSA_PSS_USING_SHA384),
    PS512(AlgorithmIdentifiers.RSA_PSS_USING_SHA512),
    NONE(AlgorithmIdentifiers.NONE)
}

enum class EncryptionAlgorithm(val value: String) {
    RSA1_5(KeyManagementAlgorithmIdentifiers.RSA1_5),
    RSA_OAEP(KeyManagementAlgorithmIdentifiers.RSA_OAEP),
    RSA_OAEP_256(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256),
    ECDH_ES(KeyManagementAlgorithmIdentifiers.ECDH_ES),
    ECDH_ES_A128KW(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW),
    ECDH_ES_A192KW(KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW),
    ECDH_ES_A256KW(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW),
    A128KW(KeyManagementAlgorithmIdentifiers.A128KW),
    A192KW(KeyManagementAlgorithmIdentifiers.A192KW),
    A256KW(KeyManagementAlgorithmIdentifiers.A256KW),
    A128GCMKW(KeyManagementAlgorithmIdentifiers.A128GCMKW),
    A192GCMKW(KeyManagementAlgorithmIdentifiers.A192GCMKW),
    A256GCMKW(KeyManagementAlgorithmIdentifiers.A256GCMKW),
    PBES2_HS256_A128KW(KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW),
    PBES2_HS384_A192KW(KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW),
    PBES2_HS512_A256KW(KeyManagementAlgorithmIdentifiers.PBES2_HS512_A256KW),
    DIRECT(KeyManagementAlgorithmIdentifiers.DIRECT),
    NONE("none")
}

enum class EncryptionEncoding(val value: String) {
    AES_128_CBC_HMAC_SHA_256(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256),
    AES_192_CBC_HMAC_SHA_384(ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384),
    AES_256_CBC_HMAC_SHA_512(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512),
    AES_128_GCM(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM),
    AES_192_GCM(ContentEncryptionAlgorithmIdentifiers.AES_192_GCM),
    AES_256_GCM(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM),
    NONE("none")
}

enum class AuthenticationMethod(val value: String) {
    BASIC("client_secret_basic"), POST("client_secret_post"),
    JWT_SECRET("client_secret_jwt"), JWT_PRIVATE("private_key_jwt"),
    NONE("none")
}

/**
 * A [Nothing] based implementation of client. This is created for test classes to easily created dummy
 * implementations without having to implement every field.
 *
 * @since inception
 */
open class NothingClient : Client, ClientSecretAware, JwksCacheAware, RequestCacheAware {
    private fun nothing(): Nothing = throw NotImplementedError("nothing client implements nothing.")
    override fun id(): String = nothing()
    override fun name(): String = nothing()
    override fun type(): ClientType = nothing()
    override fun redirectUris(): Set<String> = nothing()
    override fun responseTypes(): Set<ResponseType> = nothing()
    override fun grantTypes(): Set<GrantType> = nothing()
    override fun scopes(): Set<String> = nothing()
    override fun applicationType(): ApplicationType = nothing()
    override fun contacts(): List<String> = nothing()
    override fun logoUri(): String = nothing()
    override fun clientUri(): String = nothing()
    override fun policyUri(): String = nothing()
    override fun tosUri(): String = nothing()
    override fun jwksUri(): String = nothing()
    override fun jwks(): String = nothing()
    override fun sectorIdentifierUri(): String = nothing()
    override fun subjectType(): SubjectType = nothing()
    override fun idTokenSignedResponseAlgorithm(): SigningAlgorithm = nothing()
    override fun idTokenEncryptedResponseAlgorithm(): EncryptionAlgorithm = nothing()
    override fun idTokenEncryptedResponseEncoding(): EncryptionEncoding = nothing()
    override fun requestObjectSigningAlgorithm(): SigningAlgorithm = nothing()
    override fun requestObjectEncryptionAlgorithm(): EncryptionAlgorithm = nothing()
    override fun requestObjectEncryptionEncoding(): EncryptionEncoding = nothing()
    override fun userInfoSignedResponseAlgorithm(): SigningAlgorithm = nothing()
    override fun userInfoEncryptedResponseAlgorithm(): EncryptionAlgorithm = nothing()
    override fun userInfoEncryptedResponseEncoding(): EncryptionEncoding = nothing()
    override fun tokenEndpointAuthMethod(): AuthenticationMethod = nothing()
    override fun tokenEndpointAuthSigningAlgorithm(): SigningAlgorithm = nothing()
    override fun defaultMaxAge(): Long = nothing()
    override fun requireAuthTime(): Boolean = nothing()
    override fun defaultAcrValues(): List<String> = nothing()
    override fun requestUris(): Set<String> = nothing()
    override fun secret(): String = nothing()
    override fun jwksCache(): String = nothing()
    override fun uriForRequestCache(requestUri: String): String = nothing()
}