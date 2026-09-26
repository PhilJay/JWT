package com.philjay.jwt

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Helpers to read PEM encoded keys, such as the .p8 file downloaded from the Apple developer console.
 */
object Keys {

    /**
     * Reads a PKCS#8 private key ("-----BEGIN PRIVATE KEY-----"). The PEM header, footer and line breaks are optional.
     *
     * @throws IllegalArgumentException if the key cannot be read or does not fit the algorithm.
     */
    fun privateKey(pem: String, algorithm: Algorithm): PrivateKey {
        require(!pem.contains("BEGIN EC PRIVATE KEY") && !pem.contains("BEGIN RSA PRIVATE KEY")) {
            "Only PKCS#8 keys (BEGIN PRIVATE KEY) are supported. Convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem"
        }
        val key = try {
            KeyFactory.getInstance(algorithm.keyType).generatePrivate(PKCS8EncodedKeySpec(pemBytes(pem)))
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid ${algorithm.keyType} private key", e)
        }
        require(algorithm.accepts(key)) { "Private key does not fit algorithm $algorithm" }
        return key
    }

    /**
     * Reads an X.509 public key ("-----BEGIN PUBLIC KEY-----"). The PEM header, footer and line breaks are optional.
     *
     * @throws IllegalArgumentException if the key cannot be read or does not fit the algorithm.
     */
    fun publicKey(pem: String, algorithm: Algorithm): PublicKey {
        val key = try {
            KeyFactory.getInstance(algorithm.keyType).generatePublic(X509EncodedKeySpec(pemBytes(pem)))
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid ${algorithm.keyType} public key", e)
        }
        require(algorithm.accepts(key)) { "Public key does not fit algorithm $algorithm" }
        return key
    }

    private fun pemBytes(pem: String): ByteArray {
        val body = pem.lineSequence()
            .filterNot { it.trim().startsWith("-----") }
            .joinToString("")
            .filterNot { it.isWhitespace() }
        return Base64.getDecoder().decode(body)
    }
}
