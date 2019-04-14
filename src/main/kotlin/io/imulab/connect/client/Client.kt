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
    val id: String

    /**
     * Returns the name of the client. Implementations are encouraged to assign a default
     * name to client if none is provided by the user. However, an empty string is permitted.
     */
    val name: String

    /**
     * Returns the type of the client. Defaults to [ClientType.CONFIDENTIAL] if user didn't
     * explicitly specify.
     */
    val type: ClientType

    /**
     * Returns the registered redirect uris. Client must register at least one redirect uri.
     */
    val redirectUris: Set<String>

    /**
     * Returns the registered response types. This will be affected by the supported_response_types
     * option defined in Open ID Connect 1.0 Discovery configuration.
     */
    val responseTypes: Set<ResponseType>

    /**
     * Returns the registered grant types. This will be affected by the supported_grant_types
     * option defined in Open ID Connect 1.0 Discovery configuration.
     */
    val grantTypes: Set<GrantType>

    /**
     * Returns the registered scopes. Requests made by the client must provide scopes that is acceptable
     * by the list of scopes registered here in order to be processed. However, the notion of acceptable
     * is not limited to string equality comparison, and is subject to implementation.
     */
    val scopes: Set<String>

    /**
     * Returns the application type of the client. The value defaults to [ApplicationType.WEB] if client
     * didn't explicitly register a value.
     */
    val applicationType: ApplicationType

    /**
     * Returns the registered list of email contacts.
     *
     * In principal, the values are unique and hence should be modelled using [Set]. However, to improve
     * ease of use of the API, we are using [List] here. This is usually not a huge issue as this field
     * is informational only.
     */
    val contacts: List<String>

    /**
     * Returns the logo uri of the client. An empty string indicates no uri registered.
     */
    val logoUri: String

    /**
     * Returns the client uri. An empty string indicates no uri registered.
     */
    val clientUri: String

    /**
     * Returns the policy uri of the client. An empty string indicates no uri registered.
     */
    val policyUri: String

    /**
     * Returns the terms of service uri of the client. An empty string indicates no uri registered.
     */
    val tosUri: String

    /**
     * Returns the json web key set uri of the client. An empty string indicates no uri registered.
     *
     * This field is mutually exclusive with [jwks]. Only one of [jwks] or [jwksUri] may be provided.
     */
    val jwksUri: String

    /**
     * Returns the raw json web key set value registered by the client. An empty string indicates client
     * did not register any raw value of json web key set.
     *
     * This field is mutually exclusive with [jwksUri]. Only one of [jwks] or [jwksUri] may be provided.
     */
    val jwks: String

    /**
     * Returns the sector identifier uri of the client. Only URL with HTTPS scheme is acceptable.
     * This uri is used to validate [redirectUris] and conduct pairwise pseudonymous subject value
     * calculation. An empty string indicates no uri was registered.
     */
    val sectorIdentifierUri: String

    /**
     * Returns the subject type of the user. This value is used to determine the algorithm during the
     * pseudonymous subject value calculation. The value defaults to [SubjectType.PUBLIC] is user did
     * not explicitly register.
     */
    val subjectType: SubjectType

    /**
     * Returns the JWS algorithm used to sign the id_token response. The value should default to
     * [SigningAlgorithm.RS256] if user did not explicitly specify.
     */
    val idTokenSignedResponseAlgorithm: SigningAlgorithm

    /**
     * Returns the JWS algorithm to negotiate the encryption key for JWE. The value should default to
     * [EncryptionAlgorithm.NONE] if user did not explicitly specify.
     *
     * This field has a negative XOR relation with [idTokenEncryptedResponseEncoding]. If value is not
     * equal to [EncryptionAlgorithm.NONE], the value of [idTokenEncryptedResponseEncoding] cannot equal
     * to [EncryptionEncoding.NONE] either.
     */
    val idTokenEncryptedResponseAlgorithm: EncryptionAlgorithm

    /**
     * Returns the JWS algorithm to encode the content for JWE. The value should default to
     * [EncryptionEncoding.NONE] if user did not explicitly specify.
     *
     * This field has a negative XOR relation with [idTokenEncryptedResponseAlgorithm]. If value is not
     * equal to [EncryptionEncoding.NONE], the value of [idTokenEncryptedResponseAlgorithm] cannot equal
     *  to [EncryptionAlgorithm.NONE] either.
     */
    val idTokenEncryptedResponseEncoding: EncryptionEncoding

    /**
     * Returns the JWS algorithm client will use to sign the request object. The value should default to
     * [SigningAlgorithm.RS256] if user did not explicitly specify.
     */
    val requestObjectSigningAlgorithm: SigningAlgorithm

    /**
     * Returns the JWS algorithm client uses to negotiate the encryption key for JWE request object. If not
     * specified, should default to [EncryptionAlgorithm.NONE].
     *
     * This field has a negative XOR relation with [requestObjectEncryptionEncoding]. If value is not
     * equal to [EncryptionAlgorithm.NONE], the value of [requestObjectEncryptionEncoding] cannot equal
     * to [EncryptionEncoding.NONE] either.
     */
    val requestObjectEncryptionAlgorithm: EncryptionAlgorithm

    /**
     * Returns the JWS algorithm client uses to encode the content for JWE request object. If not specified,
     * should default to [EncryptionEncoding.NONE].
     *
     * This field has a negative XOR relation with [requestObjectEncryptionAlgorithm]. If value is not
     * equal to [EncryptionEncoding.NONE], the value of [requestObjectEncryptionAlgorithm] cannot equal
     * to [EncryptionAlgorithm.NONE] either.
     */
    val requestObjectEncryptionEncoding: EncryptionEncoding

    /**
     * Returns the signing algorithm used to sign the user info endpoint response. If not specified, should default
     * to [SigningAlgorithm.NONE], which means the endpoint will return content in application/json format.
     */
    val userInfoSignedResponseAlgorithm: SigningAlgorithm

    /**
     * Returns the JWS algorithm to negotiate the encryption key for the JWE user info response. If not specified,
     * should default to [EncryptionAlgorithm.NONE].
     *
     * This field has a negative XOR relation with [userInfoEncryptedResponseEncoding]. If value is not
     * equal to [EncryptionAlgorithm.NONE], the value of [userInfoEncryptedResponseEncoding] cannot equal
     * to [EncryptionEncoding.NONE] either.
     */
    val userInfoEncryptedResponseAlgorithm: EncryptionAlgorithm

    /**
     * Returns the JWS algorithm to encode the JWE user info response content. If not specified, should default to
     * [EncryptionEncoding.NONE].
     *
     * This field has a negative XOR relation with [userInfoEncryptedResponseAlgorithm]. If value is not
     * equal to [EncryptionEncoding.NONE], the value of [userInfoEncryptedResponseAlgorithm] cannot equal
     * to [EncryptionAlgorithm.NONE] either.
     */
    val userInfoEncryptedResponseEncoding: EncryptionEncoding

    /**
     * Returns the authentication method employed by the token endpoint. If not specified, defaults to
     * [AuthenticationMethod.BASIC].
     */
    val tokenEndpointAuthMethod: AuthenticationMethod

    /**
     * Returns the algorithm used to sign the authentication JWT used at the token endpoint. This value is only used
     * when [tokenEndpointAuthMethod] is [AuthenticationMethod.JWT_PRIVATE] or [AuthenticationMethod.JWT_SECRET].
     *
     * When [tokenEndpointAuthMethod] is [AuthenticationMethod.BASIC], [AuthenticationMethod.POST], or
     * [AuthenticationMethod.NONE], this value can default to [SigningAlgorithm.NONE]. Otherwise, client must specify
     * a not-[SigningAlgorithm.NONE] value for this field.
     */
    val tokenEndpointAuthSigningAlgorithm: SigningAlgorithm

    /**
     * Returns the default max age specified by the client. If this value is greater than zero, user authentication
     * session will be imposed an expiry constraint specified by the number of seconds in this value.
     *
     * The max age value cannot be less than zero, which means ideally we should model it using unsigned data type.
     * However, since unsigned long is still experimental in Kotlin at the time of writing. We will just use long as
     * its data type and do extra validation.
     */
    val defaultMaxAge: Long

    /**
     * Returns whether auth_time claim is required.
     */
    val requireAuthTime: Boolean

    /**
     * Returns a list of default authentication class reference values.
     */
    val defaultAcrValues: List<String>

    /**
     * Returns a list of uris, each pointing to a file that contains a request object. Upon client registration, server
     * can read from these uris and cache its content. Each uri can optionally contain a fragment calculated by hashing
     * the content with SHA-256. If such fragment is present, server will also perform hash checks on the data received.
     */
    val requestUris: Set<String>
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
    val secret: String
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
    val jwksCache: String
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
    override val id: String
        get() = nothing()
    override val name: String
        get() = nothing()
    override val type: ClientType
        get() = nothing()
    override val redirectUris: Set<String>
        get() = nothing()
    override val responseTypes: Set<ResponseType>
        get() = nothing()
    override val grantTypes: Set<GrantType>
        get() = nothing()
    override val scopes: Set<String>
        get() = nothing()
    override val applicationType: ApplicationType
        get() = nothing()
    override val contacts: List<String>
        get() = nothing()
    override val logoUri: String
        get() = nothing()
    override val clientUri: String
        get() = nothing()
    override val policyUri: String
        get() = nothing()
    override val tosUri: String
        get() = nothing()
    override val jwksUri: String
        get() = nothing()
    override val jwks: String
        get() = nothing()
    override val sectorIdentifierUri: String
        get() = nothing()
    override val subjectType: SubjectType
        get() = nothing()
    override val idTokenSignedResponseAlgorithm: SigningAlgorithm
        get() = nothing()
    override val idTokenEncryptedResponseAlgorithm: EncryptionAlgorithm
        get() = nothing()
    override val idTokenEncryptedResponseEncoding: EncryptionEncoding
        get() = nothing()
    override val requestObjectSigningAlgorithm: SigningAlgorithm
        get() = nothing()
    override val requestObjectEncryptionAlgorithm: EncryptionAlgorithm
        get() = nothing()
    override val requestObjectEncryptionEncoding: EncryptionEncoding
        get() = nothing()
    override val userInfoSignedResponseAlgorithm: SigningAlgorithm
        get() = nothing()
    override val userInfoEncryptedResponseAlgorithm: EncryptionAlgorithm
        get() = nothing()
    override val userInfoEncryptedResponseEncoding: EncryptionEncoding
        get() = nothing()
    override val tokenEndpointAuthMethod: AuthenticationMethod
        get() = nothing()
    override val tokenEndpointAuthSigningAlgorithm: SigningAlgorithm
        get() = nothing()
    override val defaultMaxAge: Long
        get() = nothing()
    override val requireAuthTime: Boolean
        get() = nothing()
    override val defaultAcrValues: List<String>
        get() = nothing()
    override val requestUris: Set<String>
        get() = nothing()
    override val secret: String
        get() = nothing()
    override val jwksCache: String
        get() = nothing()

    override fun uriForRequestCache(requestUri: String): String = nothing()
}

/**
 * A [Client] implementation which only has client_id available. This implementation is helpful
 * to be used as a placeholder when we received client_id data in request, but has not resolved
 * the client yet.
 */
class IdOnlyClient(override val id: String): NothingClient()