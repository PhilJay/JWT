package com.philjay.apnjwt


import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec


object JWT {

    /**
     * The encryption algorithm to be used to encrypt the token.
     */
    private const val algorithm = "ES256"

    /**
     * Generates a JWT token as per Apple's specifications. Does not include the required "bearer" prefix.
     *
     * @param teamId The team identifier (can be obtained from the developer console member center)
     * @param keyId  The key identifier (can be obtained when generating your private key)
     * @param secret The private key (without the header and the footer - as in (BEGIN KEY...)
     * @param mapper: A mapper to transform JWT header and payload to a json String.
     * @param encoder An encoder to base64 encode the JWT header and payload json String.
     * @param decoder A decoder to base64 decode ByteArrays.
     * @return A valid JWT token.
     */
    fun token(teamId: String, keyId: String, secret: String, mapper: Mapper, encoder: Base64Encoder,
              decoder: Base64Decoder
    ):
            String {

        val now = (System.currentTimeMillis() / 1000).toInt() // token timestamp in seconds

        val header = JWTAuthHeader(algorithm, keyId)
        val payload = JWTAuthPayload(teamId, now)

        val headerString = mapper.jsonString(header)
        val payloadString = mapper.jsonString(payload)

        val charset = StandardCharsets.UTF_8
        val base64Header = encoder.encode(headerString.toByteArray(charset))
        val base64Payload = encoder.encode(payloadString.toByteArray(charset))

        val value = "$base64Header.$base64Payload"

        return value + "." + es256(secret, value, encoder, decoder)
    }

    private fun es256(secret: String, data: String, encoder: Base64Encoder, decoder: Base64Decoder): String {

        val factory = KeyFactory.getInstance("EC")
        val keySpec = PKCS8EncodedKeySpec(decoder.decode(secret.toByteArray()))
        val key = factory.generatePrivate(keySpec)

        val algECDSAsha256 = Signature.getInstance("SHA256withECDSA")
        algECDSAsha256.initSign(key)

        algECDSAsha256.update(data.toByteArray(StandardCharsets.UTF_8))

        return encoder.encode(algECDSAsha256.sign())
    }
}

/**
 * Mapper to transform auth header and payload to a json String.
 */
interface Mapper {
    /**
     * Transforms the provided header to a json String.
     * @param header The header to transform.
     * @return A json String representing the header.
     */
    fun jsonString(header: JWTAuthHeader): String

    /**
     * Transforms the provided payload to a json String.
     * @param payload The header to transform.
     * @return A json String representing the payload.
     */
    fun jsonString(payload: JWTAuthPayload): String
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
 * JWT Authentication token header.
 */
data class JWTAuthHeader(
        /** the encryption algorithm used */
        val alg: String,
        /** the key identifier (found when generating private key) */
        val kid: String)

/**
 * JWT authentication token payload.
 */
data class JWTAuthPayload(
        /** the issuer of the token (team id found in developer member center) */
        val iss: String,
        /** token issued at timestamp in seconds since Epoch (UTC) */
        val iat: Int)