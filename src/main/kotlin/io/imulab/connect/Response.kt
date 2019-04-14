package io.imulab.connect

private const val space = " "
private const val code = "code"
private const val scope = "scope"
private const val accessToken = "access_token"
private const val expiresIn = "expires_in"
private const val tokenType = "token_type"
private const val refreshToken = "refresh_token"
private const val idToken = "id_token"

/**
 * Common structure to store response data. Since Open ID Connect 1.0 response (or OAuth 2.0 response) has cross-cut
 * concerns (authorize endpoint and token endpoint share significant amount of data, depending on flows). It is modelled
 * as a simple map. The performance impact is considered to be minimal since this is not accessed too many times.
 */
typealias Response = MutableMap<String, String>

fun Response.getCode(): String = getOrDefault(code, "")
fun Response.setCode(value: String) = put(code, value)

fun Response.setScopes(scopes: Collection<String>) = put(scope, scopes.joinToString(separator = space))
fun Response.getScope(): String = getOrDefault(scope, "")
fun Response.getScopes(): Set<String> = getScope().split(space).toSet()

fun Response.setAccessToken(token: String) = put(accessToken, token)
fun Response.getAccessToken(): String = getOrDefault(accessToken, "")

fun Response.setExpiresIn(ttl: Long) = put(expiresIn, ttl.toString())
fun Response.getExpiresIn(): Long = getOrDefault(expiresIn, "0").toLong()

fun Response.setTokenType(type: String = "Bearer") = put(tokenType, type)
fun Response.getTokenType(): String = getOrDefault(tokenType, "")

fun Response.setRefreshToken(token: String) = put(refreshToken, token)
fun Response.getRefreshToken(): String = getOrDefault(refreshToken, "")

fun Response.setIdToken(token: String) = put(idToken, token)
fun Response.getIdToken(): String = getOrDefault(idToken, "")