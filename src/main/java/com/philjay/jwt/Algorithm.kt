package com.philjay.jwt

import java.security.Key
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey

/**
 * Supported JWS signature algorithms (RFC 7518). ECDSA signatures use the raw R || S format required by JWS.
 */
enum class Algorithm(
    internal val signatureAlgorithm: String,
    internal val keyType: String,
    internal val keySize: Int
) {
    /** ECDSA with P-256 and SHA-256, used by Apple for APNs and client secrets */
    ES256("SHA256withECDSAinP1363Format", "EC", 256),
    /** ECDSA with P-384 and SHA-384 */
    ES384("SHA384withECDSAinP1363Format", "EC", 384),
    /** ECDSA with P-521 and SHA-512 */
    ES512("SHA512withECDSAinP1363Format", "EC", 521),
    /** RSA PKCS#1 v1.5 with SHA-256, used by Apple for identity tokens */
    RS256("SHA256withRSA", "RSA", 2048),
    /** RSA PKCS#1 v1.5 with SHA-384 */
    RS384("SHA384withRSA", "RSA", 2048),
    /** RSA PKCS#1 v1.5 with SHA-512 */
    RS512("SHA512withRSA", "RSA", 2048);

    /**
     * True if the key has the right type and size for this algorithm: the matching curve for ECDSA, at least 2048 bits for RSA.
     */
    fun accepts(key: Key): Boolean = when {
        keyType == "EC" && key is ECKey -> key.params.curve.field.fieldSize == keySize
        keyType == "RSA" && key is RSAKey -> key.modulus.bitLength() >= keySize
        else -> false
    }

    companion object {
        /** Finds the algorithm by its JWS name (e.g. "ES256"). Returns null for unsupported values such as "none" or "HS256". */
        fun fromName(name: String?): Algorithm? = entries.firstOrNull { it.name == name }
    }
}
