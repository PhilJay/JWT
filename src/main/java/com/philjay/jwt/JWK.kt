package com.philjay.jwt

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec

/**
 * A JSON Web Key Set (RFC 7517), e.g. the response of https://appleid.apple.com/auth/keys.
 */
open class JWKSet(val keys: List<JWKObject>)

/**
 * A JSON Web Key (RFC 7517) holding an RSA (n, e) or EC (crv, x, y) public key.
 */
open class JWKObject(
    /** key type, "RSA" or "EC" */
    val kty: String,
    /** key identifier, matched against the "kid" of a token's header */
    val kid: String? = null,
    /** intended use, only "sig" (or no value) is accepted */
    val use: String? = null,
    /** the algorithm the key is meant for, e.g. "RS256" */
    val alg: String? = null,
    /** RSA modulus (base64url) */
    val n: String? = null,
    /** RSA public exponent (base64url) */
    val e: String? = null,
    /** EC curve, "P-256", "P-384" or "P-521" */
    val crv: String? = null,
    /** EC x coordinate (base64url) */
    val x: String? = null,
    /** EC y coordinate (base64url) */
    val y: String? = null
) {

    /**
     * The algorithm this key verifies: its "alg" value, or the default for its key type when "alg" is missing.
     * Returns null if the key cannot be used with any supported algorithm.
     */
    open fun algorithm(): Algorithm? {
        if (alg != null) return Algorithm.fromName(alg)?.takeIf { it.keyType == kty }
        return when (kty) {
            "RSA" -> Algorithm.RS256
            "EC" -> curves.entries.firstOrNull { it.value.jwkName == crv }?.key
            else -> null
        }
    }

    /**
     * True if this key may verify tokens signed with the algorithm. An RSA key without "alg" fits every RSA algorithm.
     */
    open fun supports(algorithm: Algorithm): Boolean =
        if (alg == null && kty == "RSA") algorithm.keyType == "RSA" else algorithm() == algorithm

    /**
     * Turns the JWK into a public key. Returns null if the key is invalid or not a signature key.
     */
    open fun toPublicKey(): PublicKey? {
        if (use != null && use != "sig") return null
        val algorithm = algorithm() ?: return null
        return try {
            val key = when (kty) {
                "RSA" -> {
                    val modulus = BigInteger(1, decode(n) ?: return null)
                    val exponent = BigInteger(1, decode(e) ?: return null)
                    KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
                }
                "EC" -> {
                    val curve = curves[algorithm] ?: return null
                    if (curve.jwkName != crv) return null
                    val point = ECPoint(BigInteger(1, decode(x) ?: return null), BigInteger(1, decode(y) ?: return null))
                    KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, curve.params()))
                }
                else -> return null
            }
            key.takeIf { algorithm.accepts(it) }
        } catch (e: Exception) {
            null
        }
    }

    private fun decode(value: String?): ByteArray? = value?.let { Base64Url.decodeOrNull(it.trimEnd('=')) }

    private class Curve(val jwkName: String, val javaName: String) {
        fun params(): ECParameterSpec = AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec(javaName)) }
            .getParameterSpec(ECParameterSpec::class.java)
    }

    companion object {
        private val curves = mapOf(
            Algorithm.ES256 to Curve("P-256", "secp256r1"),
            Algorithm.ES384 to Curve("P-384", "secp384r1"),
            Algorithm.ES512 to Curve("P-521", "secp521r1")
        )

        /**
         * Creates a JWK from an RSA or EC public key, e.g. to publish your own key set.
         *
         * @throws IllegalArgumentException if the key does not fit the algorithm.
         */
        fun fromPublicKey(key: PublicKey, algorithm: Algorithm, kid: String? = null): JWKObject {
            require(algorithm.accepts(key)) { "Public key does not fit algorithm $algorithm" }
            return when (key) {
                is RSAPublicKey -> JWKObject(
                    kty = "RSA", kid = kid, use = "sig", alg = algorithm.name,
                    n = Base64Url.encode(key.modulus.toUnsignedBytes()),
                    e = Base64Url.encode(key.publicExponent.toUnsignedBytes())
                )
                is ECPublicKey -> {
                    val length = (algorithm.keySize + 7) / 8
                    JWKObject(
                        kty = "EC", kid = kid, use = "sig", alg = algorithm.name, crv = curves.getValue(algorithm).jwkName,
                        x = Base64Url.encode(key.w.affineX.toUnsignedBytes(length)),
                        y = Base64Url.encode(key.w.affineY.toUnsignedBytes(length))
                    )
                }
                else -> throw IllegalArgumentException("Unsupported key type ${key.algorithm}")
            }
        }

        private fun BigInteger.toUnsignedBytes(length: Int = (bitLength() + 7) / 8): ByteArray {
            val bytes = toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(length - bytes.size) + bytes
        }
    }
}
