package com.philjay.apnjwt


import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import kotlin.text.Charsets.UTF_8


object JWT {
    /**
     * The encryption algorithm to be used to encrypt the token.
     */
    const val algorithm = "ES256"

    /**
     * Generates a JWT token as per Apple's specifications. Does not include the required "bearer" prefix.
     *
     * @param teamId The team identifier (can be obtained from the developer console member center)
     * @param keyId  The key identifier (can be obtained when generating your private key)
     * @param secret The private key (without the header and the footer - as in (BEGIN KEY...)
     * @param jsonEncoder: A mapper to transform JWT header and payload to a json String.
     * @param encoder An encoder to base64 encode the JWT header and payload json String.
     * @param decoder A decoder to base64 decode ByteArrays.
     * @param charset The Charset to use for String to ByteArray encoding, defaults to UTF_8.
     * @return A valid JWT token.
     */
    fun token(
        teamId: String,
        keyId: String,
        secret: String,
        jsonEncoder: JsonEncoder<JWTAuthHeader, JWTAuthPayload>,
        encoder: Base64Encoder,
        decoder: Base64Decoder,
        charset: Charset = UTF_8
    ): String {

        val now = Instant.now().epochSecond // token timestamp in seconds

        val header = JWTAuthHeader(kid = keyId)
        val payload = JWTAuthPayload(teamId, now)

        return token(header, payload, secret, jsonEncoder, encoder, decoder, charset)
    }

    /**
     * Generates a JWT token as per Apple's specifications. Does not include the required "bearer" prefix.
     *
     * @param header The auth header usually containing algorithm and key id.
     * @param payload The payload usually containing at least the team id and timestamp.
     * @param secret The private key (without the header and the footer - as in (BEGIN KEY...)
     * @param jsonEncoder: A mapper to transform JWT header and payload to a json String.
     * @param encoder An encoder to base64 encode the JWT header and payload json String.
     * @param decoder A decoder to base64 decode ByteArrays.
     * @param charset The Charset to use for String to ByteArray encoding, defaults to UTF_8.
     * @return A valid JWT token.
     */
    fun <H : JWTAuthHeader, P : JWTAuthPayload> token(
        header: H, payload: P, secret: String, jsonEncoder: JsonEncoder<H, P>, encoder: Base64Encoder,
        decoder: Base64Decoder, charset: Charset = UTF_8
    ): String {

        val headerString = jsonEncoder.toJson(header)
        val payloadString = jsonEncoder.toJson(payload)

        val base64Header = encoder.encode(headerString.toByteArray(charset))
        val base64Payload = encoder.encode(payloadString.toByteArray(charset))

        val value = "$base64Header.$base64Payload"

        return value + "." + es256(secret, value, encoder, decoder, charset)
    }

    /**
     * Decodes the provided JWT token string and turns it into a JWTToken object for easy property access.
     * @param jwtTokenString The JWT token to decode as a String.
     * @param jsonDecoder Mapper to transform the JSON String to JSON objects.
     * @param decoder A decoder to base64 decode ByteArrays.
     * @param charset The Charset to use for String to ByteArray encoding, defaults to UTF_8.
     * @return JWT token object.
     */
    fun <H : JWTAuthHeader, P : JWTAuthPayload> decode(
        jwtTokenString: String,
        jsonDecoder: JsonDecoder<H, P>,
        decoder: Base64Decoder,
        charset: Charset = UTF_8
    ): JWTToken<H, P>? {
        val parts = jwtTokenString.split(".")
        return if (parts.size >= 2) {

            val headerJson = decoder.decode(parts[0].toByteArray(charset)).toString(charset)
            val payloadJson = decoder.decode(parts[1].toByteArray(charset)).toString(charset)

            val header: H = jsonDecoder.headerFrom(headerJson)
            val payload: P = jsonDecoder.payloadFrom(payloadJson)
            JWTToken(header, payload)
        } else {
            null
        }
    }

    private fun es256(
        secret: String,
        data: String,
        encoder: Base64Encoder,
        decoder: Base64Decoder,
        charset: Charset
    ): String {

        val factory = KeyFactory.getInstance("EC")
        val keySpec = PKCS8EncodedKeySpec(decoder.decode(secret.toByteArray(charset)))
        val key = factory.generatePrivate(keySpec)

        val algECDSAsha256 = Signature.getInstance("SHA256withECDSA")
        algECDSAsha256.initSign(key)
        algECDSAsha256.update(data.toByteArray(charset))

        return encoder.encode(algECDSAsha256.sign())
    }
}

/**
 * Mapper to transform auth header and payload to a json String.
 */
interface JsonEncoder<H : JWTAuthHeader, P : JWTAuthPayload> {
    /**
     * Transforms the provided header to a json String.
     * @param header The header to transform.
     * @return A json String representing the header.
     */
    fun toJson(header: H): String

    /**
     * Transforms the provided payload to a json String.
     * @param payload The header to transform.
     * @return A json String representing the payload.
     */
    fun toJson(payload: P): String
}

interface JsonDecoder<H : JWTAuthHeader, P : JWTAuthPayload> {
    /**
     * Transforms the provided header json String into a header object.
     * @return A header object representing the json String.
     */
    fun headerFrom(json: String): H

    /**
     * Transforms the provided payload json String into a payload object.
     * @return A payload object representing the json String.
     */
    fun payloadFrom(json: String): P
}

interface Base64Encoder {
    /**
     * Base64 encodes the provided bytes.
     * @param bytes The ByteArray to be encoded.
     * @return The encoded String.
     */
    fun encode(bytes: ByteArray): String
}

interface Base64Decoder {
    /**
     * Base64 encodes the provided bytes.
     * @param bytes The ByteArray to be decoded.
     * @return The decoded bytes.
     */
    fun decode(bytes: ByteArray): ByteArray
}

/**
 * JWTToken representation with header and payload. Used for String token decoding.
 */
open class JWTToken<H : JWTAuthHeader, P : JWTAuthPayload>(val header: H, val payload: P)

/**
 * JWT Authentication token header.
 */
open class JWTAuthHeader(
    /** the encryption algorithm used, defaults to ES256 */
    val alg: String = JWT.algorithm,
    /** the key identifier (found when generating private key) */
    val kid: String
)

/**
 * JWT authentication token payload.
 */
open class JWTAuthPayload(
    /** the issuer of the token (team id found in developer member center) */
    val iss: String,
    /** token issued at timestamp in seconds since Epoch (UTC) */
    val iat: Long
)
