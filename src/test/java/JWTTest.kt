import com.google.gson.GsonBuilder
import com.philjay.jwt.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

class CustomPayload(
    val name: String,
    iss: String? = null,
    iat: Long? = null,
    exp: Long? = null,
    nbf: Long? = null,
    aud: Any? = null,
    sub: String? = null
) : JWTAuthPayload(iss, iat, exp, nbf, aud, sub)

class JWTTest {

    private val gson = GsonBuilder().create()

    private val jsonEncoder = object : JsonEncoder<JWTAuthHeader, CustomPayload> {
        override fun toJson(header: JWTAuthHeader): String = gson.toJson(header)
        override fun toJson(payload: CustomPayload): String = gson.toJson(payload)
    }

    private val jsonDecoder = object : JsonDecoder<JWTAuthHeader, CustomPayload> {
        override fun headerFrom(json: String): JWTAuthHeader = gson.fromJson(json, JWTAuthHeader::class.java)
        override fun payloadFrom(json: String): CustomPayload = gson.fromJson(json, CustomPayload::class.java)
    }

    private val appleEncoder = object : JsonEncoder<AppleJWTAuthHeader, JWTAuthPayload> {
        override fun toJson(header: AppleJWTAuthHeader): String = gson.toJson(header)
        override fun toJson(payload: JWTAuthPayload): String = gson.toJson(payload)
    }

    private val appleDecoder = object : JsonDecoder<AppleJWTAuthHeader, AppleIdentityTokenPayload> {
        override fun headerFrom(json: String): AppleJWTAuthHeader = gson.fromJson(json, AppleJWTAuthHeader::class.java)
        override fun payloadFrom(json: String): AppleIdentityTokenPayload =
            gson.fromJson(json, AppleIdentityTokenPayload::class.java)
    }

    private val now = 1_750_000_000L
    private val clock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC)

    private val rsaKeys = keyPair("RSA", 2048)
    private val ecKeys = ecKeyPair("secp256r1")
    private val jwks = listOf(
        JWKObject.fromPublicKey(rsaKeys.public, Algorithm.RS256, kid = "rsa"),
        JWKObject.fromPublicKey(ecKeys.public, Algorithm.ES256, kid = "ec")
    )
    private val validation = JWTValidation(issuer = "issuer", audiences = setOf("client"))

    private fun keyPair(type: String, size: Int): KeyPair =
        KeyPairGenerator.getInstance(type).apply { initialize(size) }.generateKeyPair()

    private fun ecKeyPair(curve: String): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    private fun pem(keys: KeyPair): String =
        "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(keys.private.encoded) +
                "\n-----END PRIVATE KEY-----\n"

    private fun token(
        payload: CustomPayload = CustomPayload("n", iss = "issuer", iat = now, exp = now + 600, aud = "client"),
        algorithm: Algorithm = Algorithm.RS256,
        kid: String = "rsa"
    ): String {
        val keys = if (algorithm == Algorithm.RS256) rsaKeys else ecKeys
        return JWT.token(algorithm, JWTAuthHeader(algorithm.name, kid), payload, keys.private, jsonEncoder)
    }

    private fun verify(jwt: String) = JWT.verify(jwt, jwks, jsonDecoder, validation, clock)

    private fun errorOf(jwt: String) = (verify(jwt) as? JWTVerificationResult.Invalid)?.error

    @Test
    fun testDecode() {
        // dummy Apple JWT created with jwt.io
        val jwt =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkFCQ0RFRkcifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoiSkFORSJ9.aWXZy39-nV3chKPGeX8SZnK7PwuqRGxCThrvN955M0Ne4xcd7RJJyoSQEPjbok4MD2PMP7UPquPTYylYRCbsbQ"

        val token = JWT.decode(jwt, jsonDecoder)

        assertNotNull(token)
        assertEquals("ES256", token?.header?.alg)
        assertEquals("ABCDEFG", token?.header?.kid)
        assertEquals("1234567890", token?.payload?.sub)
        assertEquals("John Doe", token?.payload?.name)
        assertEquals(1516239022L, token?.payload?.iat)
        assertEquals("JANE", token?.payload?.iss)
        assertNull(JWT.decode("$jwt.extra", jsonDecoder))
    }

    @Test
    fun testAppleTokens() {
        val apns = JWT.tokenApple("teamId", "keyId", pem(ecKeys), appleEncoder, clock)

        assertTrue(JWT.verifySignature(apns, ecKeys.public, Algorithm.ES256))
        assertEquals(64, Base64.getUrlDecoder().decode(apns.substringAfterLast('.')).size)
        val apnsToken = JWT.decode(apns, appleDecoder)!!
        assertEquals("keyId", apnsToken.header.kid)
        assertEquals("teamId", apnsToken.payload.iss)
        assertEquals(now, apnsToken.payload.iat)
        assertNull(apnsToken.payload.exp)

        val secret = JWT.appleClientSecret("teamId", "keyId", "com.example.app", ecKeys.private, appleEncoder, clock = clock)
        val secretToken = JWT.decode(secret, appleDecoder)!!
        assertEquals(JWT.APPLE_ISSUER, secretToken.payload.aud)
        assertEquals("com.example.app", secretToken.payload.sub)
        assertEquals(now + 3600, secretToken.payload.exp)
        assertThrows(IllegalArgumentException::class.java) {
            JWT.appleClientSecret("t", "k", "c", ecKeys.private, appleEncoder, expiresIn = Duration.ofDays(200))
        }
    }

    @Test
    fun testVerifyAcceptsValidTokens() {
        val rs256 = verify(token())
        assertTrue(rs256.isValid)
        assertEquals("n", rs256.tokenOrNull()?.payload?.name)

        assertTrue(verify(token(algorithm = Algorithm.ES256, kid = "ec")).isValid)

        val expiredWithinLeeway = CustomPayload("n", iss = "issuer", exp = now - 30, aud = "client")
        assertTrue(verify(token(expiredWithinLeeway)).isValid)

        val audienceArray = CustomPayload("n", iss = "issuer", exp = now + 600, aud = listOf("other-app", "client"))
        assertEquals(listOf("other-app", "client"), verify(token(audienceArray)).tokenOrNull()?.payload?.audiences())
    }

    @Test
    fun testVerifyRejectsForgedTokens() {
        val valid = token()
        val (header, _, signature) = valid.split('.')
        val otherPayload = Base64Url(gson.toJson(CustomPayload("admin", iss = "issuer", exp = now + 600, aud = "client")))

        assertEquals(JWTVerificationError.INVALID_SIGNATURE, errorOf("$header.$otherPayload.$signature"))
        assertEquals(JWTVerificationError.UNSUPPORTED_ALGORITHM, errorOf("${Base64Url("""{"alg":"none"}""")}.$otherPayload."))
        assertEquals(JWTVerificationError.NO_MATCHING_KEY, errorOf(token(kid = "unknown")))
        assertEquals(JWTVerificationError.NO_MATCHING_KEY, errorOf(token(kid = "ec")))
        assertEquals(JWTVerificationError.MALFORMED, errorOf("$header.$otherPayload"))
        assertEquals(JWTVerificationError.TOO_LONG, errorOf("a".repeat(JWT.MAX_TOKEN_LENGTH + 1)))
        assertEquals(JWTVerificationError.MALFORMED, errorOf(sameBytesOtherString(token(algorithm = Algorithm.ES256, kid = "ec"))))
        assertFalse(JWT.verifySignature(valid, ecKeys.public, Algorithm.ES256))

        val weakRsa = keyPair("RSA", 1024)
        assertThrows(IllegalArgumentException::class.java) {
            JWT.token(Algorithm.RS256, JWTAuthHeader("RS256"), CustomPayload("n"), weakRsa.private, jsonEncoder)
        }
        assertThrows(IllegalArgumentException::class.java) {
            JWT.token(Algorithm.RS256, JWTAuthHeader("ES256"), CustomPayload("n"), rsaKeys.private, jsonEncoder)
        }
    }

    @Test
    fun testVerifyChecksClaims() {
        fun errorFor(payload: CustomPayload) = errorOf(token(payload))

        assertEquals(JWTVerificationError.EXPIRED, errorFor(CustomPayload("n", iss = "issuer", exp = now - 61, aud = "client")))
        assertEquals(JWTVerificationError.MISSING_EXPIRATION, errorFor(CustomPayload("n", iss = "issuer", aud = "client")))
        assertEquals(JWTVerificationError.NOT_YET_VALID, errorFor(CustomPayload("n", iss = "issuer", exp = now + 600, nbf = now + 300, aud = "client")))
        assertEquals(JWTVerificationError.ISSUED_IN_FUTURE, errorFor(CustomPayload("n", iss = "issuer", iat = now + 300, exp = now + 600, aud = "client")))
        assertEquals(JWTVerificationError.INVALID_ISSUER, errorFor(CustomPayload("n", iss = "other", exp = now + 600, aud = "client")))
        assertEquals(JWTVerificationError.INVALID_AUDIENCE, errorFor(CustomPayload("n", iss = "issuer", exp = now + 600, aud = "other-app")))
        assertEquals(JWTVerificationError.INVALID_AUDIENCE, errorFor(CustomPayload("n", iss = "issuer", exp = now + 600, aud = listOf("a", "b"))))
        assertThrows(IllegalArgumentException::class.java) { CustomPayload("n", aud = 42) }
    }

    @Test
    fun testVerifyApple() {
        val payload = AppleIdentityTokenPayload(
            iss = JWT.APPLE_ISSUER, iat = now, exp = now + 600, aud = "com.example.app", sub = "user", nonce = "abc"
        )
        val encoder = object : JsonEncoder<JWTAuthHeader, AppleIdentityTokenPayload> {
            override fun toJson(header: JWTAuthHeader): String = gson.toJson(header)
            override fun toJson(payload: AppleIdentityTokenPayload): String = gson.toJson(payload)
        }
        val identityToken = JWT.token(Algorithm.RS256, JWTAuthHeader("RS256", "rsa"), payload, rsaKeys.private, encoder)
        val clientIds = setOf("com.example.app")

        val result = JWT.verifyApple(identityToken, jwks, clientIds, appleDecoder, nonce = "abc", clock = clock)
        assertEquals("user", result.tokenOrNull()?.payload?.sub)

        val wrongNonce = JWT.verifyApple(identityToken, jwks, clientIds, appleDecoder, nonce = "xyz", clock = clock)
        assertEquals(JWTVerificationError.INVALID_NONCE, (wrongNonce as JWTVerificationResult.Invalid).error)

        val otherApp = JWT.verifyApple(identityToken, jwks, setOf("com.other.app"), appleDecoder, clock = clock)
        assertEquals(JWTVerificationError.INVALID_AUDIENCE, (otherApp as JWTVerificationResult.Invalid).error)
    }

    private fun Base64Url(json: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())

    // Changes unused bits of the last signature character: decodes to the same bytes in lenient decoders.
    private fun sameBytesOtherString(jwt: String): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val last = alphabet[alphabet.indexOf(jwt.last()) xor 1]
        return jwt.dropLast(1) + last
    }
}
