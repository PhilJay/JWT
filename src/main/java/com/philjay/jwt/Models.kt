package com.philjay.jwt

/**
 * Mapper to transform auth header and payload to a json String.
 */
interface JsonEncoder<H : JWTAuthHeader, P : JWTAuthPayload> {
    /**
     * Transforms the provided header to a json String.
     */
    fun toJson(header: H): String

    /**
     * Transforms the provided payload to a json String.
     */
    fun toJson(payload: P): String
}

/**
 * Mapper to transform json Strings to auth header and payload objects.
 */
interface JsonDecoder<H : JWTAuthHeader, P : JWTAuthPayload> {
    /**
     * Transforms the provided header json String into a header object.
     */
    fun headerFrom(json: String): H

    /**
     * Transforms the provided payload json String into a payload object.
     */
    fun payloadFrom(json: String): P
}

/**
 * A decoded JWT. Tokens from [JWT.decode] are not verified; only trust tokens returned by a successful verification.
 */
open class JWTToken<out H : JWTAuthHeader, out P : JWTAuthPayload>(
    val header: H,
    val payload: P,
    val signature: ByteArray
)

/**
 * JWT header.
 */
open class JWTAuthHeader(
    /** the signature algorithm, e.g. "ES256" */
    val alg: String,
    /** the key identifier */
    val kid: String? = null,
    /** the token type, usually "JWT" */
    val typ: String? = null
)

/**
 * JWT header for Apple (APNs and Sign in with Apple client secrets).
 */
class AppleJWTAuthHeader(
    /** the signature algorithm, defaults to ES256 */
    alg: String = Algorithm.ES256.name,
    /** the key identifier (found when generating the private key) */
    kid: String
) : JWTAuthHeader(alg, kid)

/**
 * JWT payload with the registered claims of RFC 7519. Times are seconds since Epoch (UTC).
 */
open class JWTAuthPayload(
    /** issuer, e.g. your team id */
    val iss: String? = null,
    /** issued at */
    val iat: Long? = null,
    /** expiration time */
    val exp: Long? = null,
    /** not before */
    val nbf: Long? = null,
    /** audience: a String or a List<String>, as allowed by RFC 7519. Read it with [audiences]. */
    val aud: Any? = null,
    /** subject */
    val sub: String? = null,
    /** unique token id */
    val jti: String? = null
) {
    init {
        require(aud == null || aud is String || (aud is List<*> && aud.all { it is String })) {
            "aud must be a String or a List<String>"
        }
    }

    /**
     * The "aud" values as a list, whether the token holds a single String or an array. Values that are not Strings are left out.
     */
    fun audiences(): List<String> = when (val value = aud) {
        is String -> listOf(value)
        is Collection<*> -> value.filterIsInstance<String>()
        else -> emptyList()
    }
}

/**
 * Payload of an identity token from Sign in with Apple.
 */
open class AppleIdentityTokenPayload(
    iss: String? = null,
    iat: Long? = null,
    exp: Long? = null,
    aud: Any? = null,
    sub: String? = null,
    /** the nonce your app passed to the authorization request */
    val nonce: String? = null,
    /** the user's email (may be a private relay address) */
    val email: String? = null
) : JWTAuthPayload(iss = iss, iat = iat, exp = exp, aud = aud, sub = sub)
