package com.philjay.jwt

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.time.Clock
import java.time.Duration
import kotlin.text.Charsets.UTF_8

object JWT {
    /** The "iss" of Sign in with Apple identity tokens and the "aud" of Apple client secrets. */
    const val APPLE_ISSUER = "https://appleid.apple.com"

    /** Apple rejects client secrets that are valid for longer than 6 months. */
    val APPLE_CLIENT_SECRET_MAX_LIFETIME: Duration = Duration.ofSeconds(15_777_000)

    /**
     * Default maximum JWT length in characters. Apple identity tokens are about 1 KB and most servers cap all HTTP
     * headers at 8 KB, so real tokens fit easily while oversized input is rejected before it is decoded.
     */
    const val MAX_TOKEN_LENGTH = 16 * 1024

    private const val tokenDelimiter = '.'

    /**
     * Generates a JWT for APNs token based authentication. Does not include the required "bearer" prefix.
     * APNs accepts a token for one hour, reuse it and refresh it before then.
     *
     * @param teamId The team identifier (can be obtained from the developer console member center)
     * @param keyId The key identifier (can be obtained when generating your private key)
     * @param secret The private key (.p8 content), PEM header and footer are optional
     * @param jsonEncoder A mapper to transform JWT header and payload to a json String.
     */
    fun tokenApple(
        teamId: String,
        keyId: String,
        secret: String,
        jsonEncoder: JsonEncoder<AppleJWTAuthHeader, JWTAuthPayload>,
        clock: Clock = Clock.systemUTC()
    ): String = tokenApple(teamId, keyId, Keys.privateKey(secret, Algorithm.ES256), jsonEncoder, clock)

    /**
     * Generates a JWT for APNs token based authentication with an already loaded private key.
     */
    fun tokenApple(
        teamId: String,
        keyId: String,
        privateKey: PrivateKey,
        jsonEncoder: JsonEncoder<AppleJWTAuthHeader, JWTAuthPayload>,
        clock: Clock = Clock.systemUTC()
    ): String {
        val header = AppleJWTAuthHeader(kid = keyId)
        val payload = JWTAuthPayload(iss = teamId, iat = clock.instant().epochSecond)
        return token(Algorithm.ES256, header, payload, privateKey, jsonEncoder)
    }

    /**
     * Generates the client secret for the Sign in with Apple REST API (token validation and revocation).
     *
     * @param teamId The team identifier
     * @param keyId The identifier of a key with Sign in with Apple enabled
     * @param clientId The Services ID or App ID (bundle identifier) the secret is used for
     * @param privateKey The private key of [keyId]
     * @param expiresIn How long the secret is valid, at most [APPLE_CLIENT_SECRET_MAX_LIFETIME]
     */
    fun appleClientSecret(
        teamId: String,
        keyId: String,
        clientId: String,
        privateKey: PrivateKey,
        jsonEncoder: JsonEncoder<AppleJWTAuthHeader, JWTAuthPayload>,
        expiresIn: Duration = Duration.ofHours(1),
        clock: Clock = Clock.systemUTC()
    ): String {
        require(!expiresIn.isNegative && !expiresIn.isZero && expiresIn <= APPLE_CLIENT_SECRET_MAX_LIFETIME) {
            "expiresIn must be between 1 second and $APPLE_CLIENT_SECRET_MAX_LIFETIME"
        }
        val now = clock.instant().epochSecond
        val header = AppleJWTAuthHeader(kid = keyId)
        val payload = JWTAuthPayload(iss = teamId, iat = now, exp = now + expiresIn.seconds, aud = APPLE_ISSUER, sub = clientId)
        return token(Algorithm.ES256, header, payload, privateKey, jsonEncoder)
    }

    /**
     * Generates a signed JWT String.
     *
     * @param algorithm The algorithm to sign with, must equal the "alg" of [header].
     * @param header The JWT header.
     * @param payload The JWT payload.
     * @param secret The PKCS#8 private key, PEM header and footer are optional.
     * @param jsonEncoder A mapper to transform JWT header and payload to a json String.
     * @throws IllegalArgumentException if the key does not fit the algorithm or the header.
     */
    fun <H : JWTAuthHeader, P : JWTAuthPayload> token(
        algorithm: Algorithm,
        header: H,
        payload: P,
        secret: String,
        jsonEncoder: JsonEncoder<H, P>
    ): String = token(algorithm, header, payload, Keys.privateKey(secret, algorithm), jsonEncoder)

    /**
     * Generates a signed JWT String with an already loaded private key.
     *
     * @throws IllegalArgumentException if the key does not fit the algorithm or the header.
     */
    fun <H : JWTAuthHeader, P : JWTAuthPayload> token(
        algorithm: Algorithm,
        header: H,
        payload: P,
        privateKey: PrivateKey,
        jsonEncoder: JsonEncoder<H, P>
    ): String {
        require(header.alg == algorithm.name) { "Header alg '${header.alg}' does not match algorithm $algorithm" }
        require(algorithm.accepts(privateKey)) { "Private key does not fit algorithm $algorithm" }

        val base64Header = Base64Url.encode(jsonEncoder.toJson(header).toByteArray(UTF_8))
        val base64Payload = Base64Url.encode(jsonEncoder.toJson(payload).toByteArray(UTF_8))
        val signingInput = "$base64Header$tokenDelimiter$base64Payload"

        val signature = Signature.getInstance(algorithm.signatureAlgorithm).run {
            initSign(privateKey)
            update(signingInput.toByteArray(UTF_8))
            sign()
        }
        return signingInput + tokenDelimiter + Base64Url.encode(signature)
    }

    /**
     * Decodes a JWT String WITHOUT verifying its signature or claims. Never trust the result for authentication,
     * use [verify] or [verifyApple] instead.
     *
     * @param maxLength Longer Strings are not decoded.
     * @return The decoded token, or null if it is malformed or too long.
     */
    fun <H : JWTAuthHeader, P : JWTAuthPayload> decode(
        jwtTokenString: String,
        jsonDecoder: JsonDecoder<H, P>,
        maxLength: Int = MAX_TOKEN_LENGTH
    ): JWTToken<H, P>? = if (jwtTokenString.length > maxLength) null else parse(jwtTokenString, jsonDecoder)?.token

    /**
     * Verifies only the signature of a JWT with the given public key. The algorithm comes from the caller, never
     * from the token. Does not check any claims such as "exp", "iss" or "aud".
     * Returns false for tokens longer than [MAX_TOKEN_LENGTH].
     */
    fun verifySignature(jwt: String, publicKey: PublicKey, algorithm: Algorithm): Boolean {
        if (jwt.length > MAX_TOKEN_LENGTH) return false
        val parts = jwt.split(tokenDelimiter)
        if (parts.size != 3) return false
        val signature = Base64Url.decodeOrNull(parts[2]) ?: return false
        return verifySignature("${parts[0]}$tokenDelimiter${parts[1]}", signature, publicKey, algorithm)
    }

    /**
     * Verifies only the signature of a JWT with the given JWK. Does not check any claims such as "exp", "iss" or "aud".
     * Returns false for tokens longer than [MAX_TOKEN_LENGTH].
     */
    fun verifySignature(jwt: String, jwk: JWKObject): Boolean {
        val algorithm = jwk.algorithm() ?: return false
        val key = jwk.toPublicKey() ?: return false
        return verifySignature(jwt, key, algorithm)
    }

    /**
     * Verifies the signature and the claims of a JWT.
     *
     * Tokens longer than [JWTValidation.maxTokenLength] are rejected before decoding.
     * The key is picked from [keys] by the token's "kid". Without a "kid", every key that fits the algorithm is tried.
     * The token's "alg" must be supported and fit the key.
     * Afterwards "exp", "nbf", "iat", "iss" and "aud" are checked as configured in [validation].
     *
     * @param jwt The JWT String to verify.
     * @param keys The trusted public keys, e.g. from a JWKS endpoint.
     * @param jsonDecoder Mapper to transform the JSON Strings to header and payload objects.
     * @param validation The claim checks.
     * @param clock The clock to check the time based claims against.
     */
    fun <H : JWTAuthHeader, P : JWTAuthPayload> verify(
        jwt: String,
        keys: List<JWKObject>,
        jsonDecoder: JsonDecoder<H, P>,
        validation: JWTValidation,
        clock: Clock = Clock.systemUTC()
    ): JWTVerificationResult<H, P> {
        if (jwt.length > validation.maxTokenLength) return invalid(JWTVerificationError.TOO_LONG)
        val parsed = parse(jwt, jsonDecoder) ?: return invalid(JWTVerificationError.MALFORMED)
        val header = parsed.token.header
        val payload = parsed.token.payload

        val algorithm = Algorithm.fromName(header.alg) ?: return invalid(JWTVerificationError.UNSUPPORTED_ALGORITHM)
        val candidates = keys
            .filter { header.kid == null || it.kid == header.kid }
            .filter { it.supports(algorithm) }
            .mapNotNull { it.toPublicKey() }
        if (candidates.isEmpty()) return invalid(JWTVerificationError.NO_MATCHING_KEY)
        if (candidates.none { verifySignature(parsed.signingInput, parsed.token.signature, it, algorithm) }) {
            return invalid(JWTVerificationError.INVALID_SIGNATURE)
        }

        val now = clock.instant().epochSecond
        val leeway = validation.leewaySeconds
        val exp = payload.exp
        val nbf = payload.nbf
        val iat = payload.iat
        return when {
            exp == null && validation.requireExpiration -> invalid(JWTVerificationError.MISSING_EXPIRATION)
            exp != null && now - leeway >= exp -> invalid(JWTVerificationError.EXPIRED)
            nbf != null && now + leeway < nbf -> invalid(JWTVerificationError.NOT_YET_VALID)
            iat != null && now + leeway < iat -> invalid(JWTVerificationError.ISSUED_IN_FUTURE)
            validation.issuer != null && payload.iss != validation.issuer -> invalid(JWTVerificationError.INVALID_ISSUER)
            validation.audiences.isNotEmpty() && payload.audiences().none { it in validation.audiences } -> invalid(JWTVerificationError.INVALID_AUDIENCE)
            else -> JWTVerificationResult.Valid(parsed.token)
        }
    }

    /**
     * Verifies an identity token from Sign in with Apple: signature, expiration, issuer, audience and optionally the nonce.
     *
     * @param identityToken The identity token sent by your app.
     * @param keys Apple's current public keys from https://appleid.apple.com/auth/keys (cache them, refresh on unknown "kid").
     * @param clientIds Your App IDs (bundle identifiers) and Services IDs that may receive tokens.
     * @param jsonDecoder Mapper to transform the JSON Strings to header and payload objects.
     * @param nonce The nonce you expect in the token, exactly as sent to Apple. Null skips the nonce check.
     */
    fun <H : JWTAuthHeader, P : AppleIdentityTokenPayload> verifyApple(
        identityToken: String,
        keys: List<JWKObject>,
        clientIds: Set<String>,
        jsonDecoder: JsonDecoder<H, P>,
        nonce: String? = null,
        clock: Clock = Clock.systemUTC()
    ): JWTVerificationResult<H, P> {
        require(clientIds.isNotEmpty()) { "clientIds must not be empty" }
        val result = verify(identityToken, keys, jsonDecoder, JWTValidation(APPLE_ISSUER, clientIds), clock)
        val token = result.tokenOrNull() ?: return result
        if (nonce != null) {
            val tokenNonce = token.payload.nonce ?: return invalid(JWTVerificationError.INVALID_NONCE)
            if (!MessageDigest.isEqual(tokenNonce.toByteArray(UTF_8), nonce.toByteArray(UTF_8))) {
                return invalid(JWTVerificationError.INVALID_NONCE)
            }
        }
        return result
    }

    private class ParsedToken<H : JWTAuthHeader, P : JWTAuthPayload>(val token: JWTToken<H, P>, val signingInput: String)

    private fun <H : JWTAuthHeader, P : JWTAuthPayload> parse(jwt: String, jsonDecoder: JsonDecoder<H, P>): ParsedToken<H, P>? {
        val parts = jwt.split(tokenDelimiter)
        if (parts.size != 3) return null
        val headerJson = Base64Url.decodeOrNull(parts[0])?.toString(UTF_8) ?: return null
        val payloadJson = Base64Url.decodeOrNull(parts[1])?.toString(UTF_8) ?: return null
        val signature = Base64Url.decodeOrNull(parts[2]) ?: return null
        return try {
            val header: H? = jsonDecoder.headerFrom(headerJson)
            val payload: P? = jsonDecoder.payloadFrom(payloadJson)
            if (header == null || payload == null) return null
            ParsedToken(JWTToken(header, payload, signature), "${parts[0]}$tokenDelimiter${parts[1]}")
        } catch (e: Exception) {
            null
        }
    }

    private fun verifySignature(signingInput: String, signature: ByteArray, key: PublicKey, algorithm: Algorithm): Boolean {
        if (!algorithm.accepts(key)) return false
        return try {
            Signature.getInstance(algorithm.signatureAlgorithm).run {
                initVerify(key)
                update(signingInput.toByteArray(UTF_8))
                verify(signature)
            }
        } catch (e: GeneralSecurityException) {
            false
        }
    }

    private fun invalid(error: JWTVerificationError) = JWTVerificationResult.Invalid(error)
}
