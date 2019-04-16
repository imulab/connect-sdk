package io.imulab.connect

import io.imulab.connect.client.Client
import io.imulab.connect.client.GrantType
import io.imulab.connect.client.ResponseType
import java.time.LocalDateTime
import java.util.*

/**
 * Common interface for authorize request and token request.
 */
interface Request {
    /**
     * The unique identifier for this request
     */
    val id: String

    /**
     * The request time.
     */
    val requestedAt: LocalDateTime

    /**
     * The client associated with this request.
     */
    val client: Client

    /**
     * The requested redirect_uri for this request.
     */
    val redirectUri: String

    /**
     * The requested scopes for this request.
     */
    val scopes: Set<String>

    /**
     * The long living session information associated with this request.
     */
    val session: Session

    /**
     * Reference to unparsed values for this request.
     */
    val rawValues: Map<String, String>
}

/**
 * Interface for Open ID Connect 1.0 authorize request
 */
interface AuthorizeRequest : Request {
    /**
     * The requested response types.
     */
    val responseTypes: Set<ResponseType>

    /**
     * The state parameter
     */
    val state: String

    /**
     * The requested response mode. Default to [ResponseMode.QUERY].
     */
    val responseMode: ResponseMode

    /**
     * The nonce of the request. Sufficient entropy is recommended.
     */
    val nonce: String

    /**
     * The display parameter value.
     */
    val display: Display

    /**
     * The requested prompt parameters.
     */
    val prompt: Set<Prompt>

    /**
     * The request max_age, default to 0.
     */
    val maxAge: Long

    /**
     * The preferred list of locales for UI display.
     */
    val uiLocales: List<String>

    /**
     * The id_token_hint parameter. This can be used as a hint for authentication when prompt=none
     */
    val idTokenHint: String

    /**
     * The login_hint parameter.
     */
    val loginHint: String

    /**
     * A list of preferred authentication class reference values.
     */
    val acrValues: List<String>

    /**
     * A list of preferred locales for the claims
     */
    val claimsLocales: List<String>

    /**
     * Requested claims.
     *
     * Given the dynamic nature of claims, it is modelled use string based maps.
     */
    val claims: Map<String, Any>

    /**
     * The raw request parameter
     */
    val request: String

    /**
     * The request_uri parameter
     */
    val requestUri: String

    /**
     * The registration parameter for dynamic client registration.
     */
    val registration: String

    /**
     * Mark the given [responseType] as handled.
     */
    fun markResponseTypeAsHandled(responseType: ResponseType)

    /**
     * Returns true if the given [responseType] has been marked handled by calling [markResponseTypeAsHandled].
     */
    fun isResponseTypeHandled(responseType: ResponseType): Boolean

    /**
     * Returns true if all response types have been handled.
     */
    fun hasAllResponseTypesBeenHandled(): Boolean = responseTypes.all { isResponseTypeHandled(it) }

    /**
     * Merge the [other] authorize request with this one.
     *
     * When [hard] is true, values from this request will be forcefully replaced provided that values from [other] is
     * not null or empty
     *
     * When [hard] is false, values from this request will only be replaced when they are null or empty.
     *
     * This method should not touch system generated values such as id, request time, session, etc.
     */
    fun mergeWith(other: AuthorizeRequest, hard: Boolean = true)
}

/**
 * Interface for a token request.
 */
interface TokenRequest : Request {
    /**
     * The requested grant types.
     */
    val grantTypes: Set<GrantType>

    /**
     * The authorization code, if grant_type=authorization_code
     */
    val code: String

    /**
     * The refresh token, if grant_type=refresh_token
     */
    val refreshToken: String

    /**
     * Merge with another [TokenRequest]. Replace value only when self is empty or nil and [other] is not.
     */
    fun mergeWith(other: TokenRequest, hard: Boolean = true)
}

/**
 * Interface for a session.
 */
interface Session {
    /**
     * The session user subject identifier.
     */
    var subject: String

    /**
     * The session user subject identifier after the pseudonymous subject value calculation.
     */
    var obfuscatedSubject: String

    /**
     * Id of the client that started the session.
     */
    var clientId: String

    /**
     * Id of the request that saved this session.
     */
    var savedByRequestId: String

    /**
     * The determined redirect_uri to be used for this request. This is not necessarily the same with
     * requested redirect_uri.
     */
    var finalRedirectUri: String

    /**
     * The in-effect authorization code associated with this session.
     */
    var liveAuthorizationCode: String

    /**
     * The in-effect access token associated with this session.
     */
    var liveAccessToken: String

    /**
     * The in-effect refresh token associated with this ession.
     */
    var liveRefreshToken: String

    /**
     * The scopes granted by the user.
     */
    val grantedScopes: MutableSet<String>

    /**
     * The claims to be included in access tokens.
     */
    val accessClaims: MutableMap<String, Any>

    /**
     * The claims to be included in id tokens.
     */
    val idClaims: MutableMap<String, Any>

    /**
     * The authentication time
     */
    val authTime: LocalDateTime?

    /**
     * The authentication class references satisfied by the authentication.
     */
    val acrValues: MutableList<String>

    /**
     * The nonce value to be included in the id token.
     */
    var nonce: String

    /**
     * Replace this session with the [other] session. Keep existing values if the values from [other] is nil or empty.
     */
    fun replacedWith(other: Session)

    /**
     * Convenience method to test if refresh token should be generated
     */
    fun authorizedRefreshToken(): Boolean = grantedScopes.contains(OFFLINE_ACCESS)

    /**
     * Convenience method to test if id token should be generated
     */
    fun authorizeIdToken(): Boolean = grantedScopes.contains(OPEN_ID)
}

/**
 * Default implementation of [AuthorizeRequest].
 */
class ConnectAuthorizeRequest(
    override var id: String = UUID.randomUUID().toString(),
    override var requestedAt: LocalDateTime = LocalDateTime.now(),
    var _client: Client? = null,
    override var redirectUri: String = "",
    override val scopes: MutableSet<String> = mutableSetOf(),
    override var session: Session = ConnectSession(),
    var _rawValues: Map<String, String>? = null,
    override val responseTypes: MutableSet<ResponseType> = mutableSetOf(),
    override var state: String = "",
    var _responseMode: ResponseMode? = null,
    override var nonce: String = "",
    var _display: Display? = null,
    override val prompt: MutableSet<Prompt> = mutableSetOf(),
    override var maxAge: Long = 0,
    override val uiLocales: MutableList<String> = mutableListOf(),
    override var idTokenHint: String = "",
    override var loginHint: String = "",
    override val acrValues: MutableList<String> = mutableListOf(),
    override val claimsLocales: MutableList<String> = mutableListOf(),
    override var claims: MutableMap<String, Any> = mutableMapOf(),
    override var request: String = "",
    override var requestUri: String = "",
    override var registration: String = "",
    private val _handled: MutableSet<ResponseType> = mutableSetOf()
) : AuthorizeRequest {
    override val client: Client
        get() = _client ?: notSet()
    override val rawValues: Map<String, String>
        get() = _rawValues ?: notSet()
    override val responseMode: ResponseMode
        get() = _responseMode ?: notSet()
    override val display: Display
        get() = _display ?: notSet()

    private fun notSet(): Nothing = throw RuntimeException("value is not set")

    override fun markResponseTypeAsHandled(responseType: ResponseType) {
        _handled.add(responseType)
    }

    override fun isResponseTypeHandled(responseType: ResponseType): Boolean =
        _handled.contains(responseType)

    private fun AuthorizeRequest.tryClient(): Client? = try {
        this.client
    } catch (t: Throwable) {
        null
    }

    private fun AuthorizeRequest.tryRawValues(): Map<String, String>? = try {
        this.rawValues
    } catch (t: Throwable) {
        null
    }

    private fun AuthorizeRequest.tryResponseMode(): ResponseMode? = try {
        this.responseMode
    } catch (t: Throwable) {
        null
    }

    private fun AuthorizeRequest.tryDisplay(): Display? = try {
        this.display
    } catch (t: Throwable) {
        null
    }

    override fun mergeWith(other: AuthorizeRequest, hard: Boolean) {
        if ((hard && other.tryClient() != null) || this._client == null)
            this._client = other.tryClient()

        if ((hard && other.redirectUri.isNotEmpty()) || this.redirectUri.isEmpty())
            this.redirectUri = other.redirectUri

        if ((hard && other.scopes.isNotEmpty()) || this.scopes.isEmpty()) {
            this.scopes.clear()
            this.scopes.addAll(other.scopes)
        }

        if ((hard && other.tryRawValues() != null) || this._rawValues == null)
            this._rawValues = other.tryRawValues()

        if ((hard && other.responseTypes.isNotEmpty()) || this.responseTypes.isEmpty()) {
            this.responseTypes.clear()
            this.responseTypes.addAll(other.responseTypes)
        }

        if ((hard && other.state.isNotEmpty()) || this.state.isEmpty())
            this.state = other.state

        if ((hard && other.tryResponseMode() != null) || this._responseMode == null)
            this._responseMode = other.tryResponseMode()

        if ((hard && other.nonce.isNotEmpty()) || this.nonce.isEmpty())
            this.nonce = other.nonce

        if ((hard && other.tryDisplay() != null) || this._display == null)
            this._display = other.tryDisplay()

        if ((hard && other.prompt.isNotEmpty()) || this.prompt.isEmpty()) {
            this.prompt.clear()
            this.prompt.addAll(other.prompt)
        }

        if ((hard && other.maxAge > 0) || this.maxAge == 0L)
            this.maxAge = other.maxAge

        if ((hard && other.uiLocales.isNotEmpty()) || this.uiLocales.isEmpty()) {
            this.uiLocales.clear()
            this.uiLocales.addAll(other.uiLocales)
        }

        if ((hard || other.idTokenHint.isNotEmpty()) || this.idTokenHint.isEmpty())
            this.idTokenHint = other.idTokenHint

        if ((hard || other.loginHint.isNotEmpty()) || this.loginHint.isEmpty())
            this.loginHint = other.loginHint

        if ((hard || other.acrValues.isNotEmpty()) || this.acrValues.isEmpty()) {
            this.acrValues.clear()
            this.acrValues.addAll(other.acrValues)
        }

        if ((hard || other.claimsLocales.isNotEmpty()) || this.claimsLocales.isEmpty()) {
            this.claimsLocales.clear()
            this.claimsLocales.addAll(other.claimsLocales)
        }

        if ((hard || other.claims.isNotEmpty()) || this.claims.isEmpty()) {
            this.claims.clear()
            this.claims.putAll(other.claims)
        }

        if ((hard || other.request.isNotEmpty()) || this.request.isEmpty())
            this.request = other.request

        if ((hard || other.requestUri.isNotEmpty()) || this.requestUri.isEmpty())
            this.requestUri = other.requestUri

        if ((hard || other.registration.isNotEmpty()) || this.registration.isEmpty())
            this.registration = other.registration
    }
}

/**
 * Baked-in authorize request with default values. This is used to be merged with the authorize request parsed from
 * HTTP parameters, right before continue merging the one resolved from request parameters.
 */
val DefaultAuthorizeRequestValues = ConnectAuthorizeRequest(
    id = "",
    _responseMode = ResponseMode.QUERY,
    _display = Display.PAGE
)

/**
 * Default implementation of [TokenRequest].
 */
class ConnectTokenRequest(
    override var id: String = UUID.randomUUID().toString(),
    override var requestedAt: LocalDateTime = LocalDateTime.now(),
    var _client: Client? = null,
    override var redirectUri: String = "",
    override val scopes: MutableSet<String> = mutableSetOf(),
    override var session: Session = ConnectSession(),
    var _rawValues: Map<String, String>? = null,
    override val grantTypes: MutableSet<GrantType> = mutableSetOf(),
    override var code: String = "",
    override var refreshToken: String = ""
): TokenRequest {
    override val client: Client
        get() = _client ?: notSet()
    override val rawValues: Map<String, String>
        get() = _rawValues ?: notSet()

    private fun notSet(): Nothing = throw RuntimeException("value is not set")

    private fun TokenRequest.tryClient(): Client? = try {
        this.client
    } catch (t: Throwable) {
        null
    }

    private fun TokenRequest.tryRawValues(): Map<String, String>? = try {
        this.rawValues
    } catch (t: Throwable) {
        null
    }

    override fun mergeWith(other: TokenRequest, hard: Boolean) {
        if ((hard && other.tryClient() != null) || this._client == null)
            this._client = other.tryClient()

        if ((hard && other.redirectUri.isNotEmpty()) || this.redirectUri.isEmpty())
            this.redirectUri = other.redirectUri

        if ((hard && other.scopes.isNotEmpty()) || this.scopes.isEmpty()) {
            this.scopes.clear()
            this.scopes.addAll(other.scopes)
        }

        if ((hard && other.tryRawValues() != null) || this._rawValues == null)
            this._rawValues = other.tryRawValues()

        if ((hard && other.grantTypes.isNotEmpty()) || this.grantTypes.isEmpty()) {
            this.grantTypes.clear()
            this.grantTypes.addAll(other.grantTypes)
        }

        if ((hard && other.code.isNotEmpty()) || this.code.isEmpty())
            code = other.code

        if ((hard && other.refreshToken.isNotEmpty()) || this.refreshToken.isEmpty())
            refreshToken = other.refreshToken
    }
}

/**
 * Default implementation of [Session].
 */
class ConnectSession(
    override var subject: String = "",
    override var obfuscatedSubject: String = "",
    override var clientId: String = "",
    override var savedByRequestId: String = "",
    override var finalRedirectUri: String = "",
    override var liveAuthorizationCode: String = "",
    override var liveAccessToken: String = "",
    override var liveRefreshToken: String = "",
    override val grantedScopes: MutableSet<String> = mutableSetOf(),
    override var accessClaims: MutableMap<String, Any> = mutableMapOf(),
    override var idClaims: MutableMap<String, Any> = mutableMapOf(),
    override var authTime: LocalDateTime? = null,
    override val acrValues: MutableList<String> = mutableListOf(),
    override var nonce: String = ""
) : Session {

    override fun replacedWith(other: Session) {
        if (other.subject.isNotEmpty())
            this.subject = other.subject
        if (other.obfuscatedSubject.isNotEmpty())
            this.obfuscatedSubject = other.obfuscatedSubject
        if (other.clientId.isNotEmpty())
            this.clientId = other.clientId
        if (other.savedByRequestId.isNotEmpty())
            this.savedByRequestId = other.savedByRequestId
        if (other.finalRedirectUri.isNotEmpty())
            this.finalRedirectUri = other.finalRedirectUri
        if (other.liveAuthorizationCode.isNotEmpty())
            this.liveAuthorizationCode = other.liveAuthorizationCode
        if (other.liveAccessToken.isNotEmpty())
            this.liveAccessToken = other.liveAccessToken
        if (other.liveRefreshToken.isNotEmpty())
            this.liveRefreshToken = other.liveRefreshToken
        if (other.grantedScopes.isNotEmpty()) {
            this.grantedScopes.clear()
            this.grantedScopes.addAll(other.grantedScopes)
        }
        if (other.accessClaims.isNotEmpty())
            this.accessClaims = other.accessClaims
        if (other.idClaims.isNotEmpty())
            this.idClaims = other.idClaims
        if (other.authTime != null)
            this.authTime = other.authTime
        if (other.acrValues.isNotEmpty()) {
            this.acrValues.clear()
            this.acrValues.addAll(other.acrValues)
        }
        if (other.nonce.isNotEmpty())
            this.nonce = other.nonce
    }
}

enum class ResponseMode(val value: String) {
    QUERY("query"), FRAGMENT("fragment");

    companion object {
        @JvmStatic
        fun parse(value: String): ResponseMode = values().find { it.value == value }
            ?: throw IllegalArgumentException("$value is not a valid response mode.")
    }
}

enum class Display(val value: String) {
    PAGE("page"), POPUP("popup"), TOUCH("touch"), WAP("wap");

    companion object {
        @JvmStatic
        fun parse(value: String): Display = values().find { it.value == value }
            ?: throw IllegalArgumentException("$value is not a valid display.")
    }
}

enum class Prompt(val value: String) {
    NONE("none"), LOGIN("login"), CONSENT("consent"), SELECT_ACCOUNT("select_account");

    companion object {
        @JvmStatic
        fun parse(value: String): Prompt = values().find { it.value == value }
            ?: throw IllegalArgumentException("$value is not a valid prompt.")
    }
}