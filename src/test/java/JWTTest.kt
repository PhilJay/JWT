import com.google.gson.GsonBuilder
import com.philjay.jwt.*
import org.apache.commons.codec.binary.Base64
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class JWTTest {

    private val gson = GsonBuilder().create()

    private val jsonEncoder = object : JsonEncoder<JWTAuthHeader, CustomJWTAuthPayload> {
        override fun toJson(header: JWTAuthHeader): String {
            return gson.toJson(header, JWTAuthHeader::class.java)
        }

        override fun toJson(payload: CustomJWTAuthPayload): String {
            return gson.toJson(payload, CustomJWTAuthPayload::class.java)
        }
    }

    private val jsonDecoder = object : JsonDecoder<JWTAuthHeader, CustomJWTAuthPayload> {

        override fun headerFrom(json: String): JWTAuthHeader {
            return gson.fromJson(json, JWTAuthHeader::class.java)
        }

        override fun payloadFrom(json: String): CustomJWTAuthPayload {
            return gson.fromJson(json, CustomJWTAuthPayload::class.java)
        }
    }

    private val encoder = object : Base64Encoder {
        override fun encodeURLSafe(bytes: ByteArray): String {
            return Base64.encodeBase64URLSafeString(bytes)
        }

        override fun encode(bytes: ByteArray): String {
            return Base64.encodeBase64String(bytes)
        }
    }

    private val decoder = object : Base64Decoder {
        override fun decode(bytes: ByteArray): ByteArray {
            return Base64.decodeBase64(bytes)
        }

        override fun decode(string: String): ByteArray {
            return Base64.decodeBase64(string)
        }
    }

    @Test
    fun testDecode() {

        // dummy JWT created with jwt.io
        val jwt =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkFCQ0RFRkcifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoiSkFORSJ9.aWXZy39-nV3chKPGeX8SZnK7PwuqRGxCThrvN955M0Ne4xcd7RJJyoSQEPjbok4MD2PMP7UPquPTYylYRCbsbQ"

        val jwtObject = JWT.decode(jwt, jsonDecoder, decoder)

        assertNotNull(jwtObject)
        assertEquals("ES256", jwtObject?.header?.alg)
        assertEquals("ABCDEFG", jwtObject?.header?.kid)

        assertEquals("1234567890", jwtObject?.payload?.sub)
        assertEquals("John Doe", jwtObject?.payload?.name)
        assertEquals(1516239022L, jwtObject?.payload?.iat)
        assertEquals("JANE", jwtObject?.payload?.iss)
    }

    @Test
    fun testEncodeDecode() {

        val nowSeconds = Instant.now().epochSecond
        val expSeconds = nowSeconds + 3600

        // dummy key created in Apple dev console (without header & footer)
        val secret = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgofYVrV6I5TvcM1Gc\n" +
                "TxiNYa/K30VltjNMg0bupcr9VfagCgYIKoZIzj0DAQehRANCAATc/L5AvAOgsTM5\n" +
                "h07NRuxi4rU4JWVO7md6wTiJQS3SkMAiyzvSmMXCPf6x6tKyQeppM0jI7XWz+cjo\n" +
                "Q3raiQbh"

        val header = JWTAuthHeader(kid = "KEYID") // dummy key id

        val payload = CustomJWTAuthPayload("com.philjay.jwt", "test", "ISS", nowSeconds, expSeconds)

        val jwtString = JWT.token(header, payload, secret, jsonEncoder, encoder, decoder)
        assertNotNull(jwtString)

        val jwtObject = JWT.decode(jwtString, jsonDecoder, decoder)

        assertNotNull(jwtObject)
        assertEquals("ES256", jwtObject?.header?.alg)
        assertEquals("KEYID", jwtObject?.header?.kid)

        assertEquals("com.philjay.jwt", jwtObject?.payload?.sub)
        assertEquals("test", jwtObject?.payload?.name)
        assertEquals(nowSeconds, jwtObject?.payload?.iat)
        assertEquals(expSeconds, jwtObject?.payload?.exp)
        assertEquals("ISS", jwtObject?.payload?.iss)
    }
}