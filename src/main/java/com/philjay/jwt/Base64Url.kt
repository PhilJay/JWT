package com.philjay.jwt

import java.util.Base64

internal object Base64Url {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    /**
     * Decodes unpadded base64url. Returns null for any other input, including non-canonical encodings,
     * so that one token has exactly one valid string form.
     */
    fun decodeOrNull(value: String): ByteArray? {
        if (value.contains('=')) return null
        val bytes = try {
            decoder.decode(value)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return if (encode(bytes) == value) bytes else null
    }
}
