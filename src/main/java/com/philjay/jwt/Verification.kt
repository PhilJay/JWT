package com.philjay.jwt

/**
 * Claim checks done by [JWT.verify] after the signature is valid.
 *
 * [issuer] and [audiences] have no defaults on purpose: pass null or an empty set only if you really want to accept any value.
 */
class JWTValidation(
    /** the required "iss" value, or null to accept any issuer */
    val issuer: String?,
    /** the accepted "aud" values (e.g. your client ids), or empty to accept any audience. A token with an "aud" array is accepted if one of its values matches. */
    val audiences: Set<String>,
    /** allowed clock difference for "exp", "nbf" and "iat" */
    val leewaySeconds: Long = 60,
    /** reject tokens without an "exp" claim */
    val requireExpiration: Boolean = true,
    /** reject longer tokens before decoding them */
    val maxTokenLength: Int = JWT.MAX_TOKEN_LENGTH
) {
    init {
        require(leewaySeconds >= 0) { "leewaySeconds must not be negative" }
        require(maxTokenLength > 0) { "maxTokenLength must be positive" }
    }
}

/**
 * Result of [JWT.verify]. Only [Valid] tokens can be trusted.
 */
sealed class JWTVerificationResult<out H : JWTAuthHeader, out P : JWTAuthPayload> {
    /** The signature and all configured claims are valid. */
    class Valid<out H : JWTAuthHeader, out P : JWTAuthPayload>(val token: JWTToken<H, P>) : JWTVerificationResult<H, P>()
    /** Verification failed for the given reason. */
    class Invalid(val error: JWTVerificationError) : JWTVerificationResult<Nothing, Nothing>() {
        override fun toString() = "Invalid($error)"
    }

    /** True if this is [Valid]. */
    val isValid: Boolean get() = this is Valid

    /** The verified token, or null if verification failed. */
    fun tokenOrNull(): JWTToken<H, P>? = when (this) {
        is Valid -> token
        is Invalid -> null
    }
}

/**
 * The reason why [JWT.verify] or [JWT.verifyApple] rejected a token. The checks run in the order listed here.
 */
enum class JWTVerificationError {
    /** longer than [JWTValidation.maxTokenLength] */
    TOO_LONG,
    /** not three base64url parts, or header / payload could not be parsed */
    MALFORMED,
    /** "alg" is missing or not supported (e.g. "none") */
    UNSUPPORTED_ALGORITHM,
    /** no key matches the token's "kid" and algorithm */
    NO_MATCHING_KEY,
    /** the signature does not match any of the candidate keys */
    INVALID_SIGNATURE,
    /** "exp" is missing while [JWTValidation.requireExpiration] is true */
    MISSING_EXPIRATION,
    /** "exp" is in the past, allowing for the leeway */
    EXPIRED,
    /** "nbf" is in the future, allowing for the leeway */
    NOT_YET_VALID,
    /** "iat" is in the future, allowing for the leeway */
    ISSUED_IN_FUTURE,
    /** "iss" is not [JWTValidation.issuer] */
    INVALID_ISSUER,
    /** none of the "aud" values is in [JWTValidation.audiences] */
    INVALID_AUDIENCE,
    /** "nonce" is missing or not the expected value (only [JWT.verifyApple]) */
    INVALID_NONCE
}
