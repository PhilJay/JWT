import com.google.gson.GsonBuilder
import com.philjay.jwt.*
import org.apache.commons.codec.binary.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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
    private val appleJsonDecoder = object : JsonDecoder<AppleJWTAuthHeader, CustomJWTAuthPayload> {

        override fun headerFrom(json: String): AppleJWTAuthHeader {
            return gson.fromJson(json, AppleJWTAuthHeader::class.java)
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

        // dummy Apple JWT created with jwt.io
        val jwt =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkFCQ0RFRkcifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoiSkFORSJ9.aWXZy39-nV3chKPGeX8SZnK7PwuqRGxCThrvN955M0Ne4xcd7RJJyoSQEPjbok4MD2PMP7UPquPTYylYRCbsbQ"

        val jwtObject = JWT.decode(jwt, appleJsonDecoder, decoder)

        assertNotNull(jwtObject)
        assertEquals("ES256", jwtObject?.header?.alg)
        assertEquals("ABCDEFG", jwtObject?.header?.kid)

        assertEquals("1234567890", jwtObject?.payload?.sub)
        assertEquals("John Doe", jwtObject?.payload?.name)
        assertEquals(1516239022L, jwtObject?.payload?.iat)
        assertEquals("JANE", jwtObject?.payload?.iss)
    }

    @Test
    fun testTokenApple() {

        val jsonEncoder = object : JsonEncoder<AppleJWTAuthHeader, JWTAuthPayload> {
            override fun toJson(header: AppleJWTAuthHeader): String {
                return gson.toJson(header, AppleJWTAuthHeader::class.java)
            }

            override fun toJson(payload: JWTAuthPayload): String {
                return gson.toJson(payload, JWTAuthPayload::class.java)
            }
        }

        val nowSeconds = Instant.now().epochSecond
        // dummy key created in Apple dev console (without header & footer)
        val secret = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgofYVrV6I5TvcM1Gc\n" +
                "TxiNYa/K30VltjNMg0bupcr9VfagCgYIKoZIzj0DAQehRANCAATc/L5AvAOgsTM5\n" +
                "h07NRuxi4rU4JWVO7md6wTiJQS3SkMAiyzvSmMXCPf6x6tKyQeppM0jI7XWz+cjo\n" +
                "Q3raiQbh"

        val jwtString = JWT.tokenApple(
            teamId = "teamId",
            keyId = "keyId",
            secret = secret,
            jsonEncoder = jsonEncoder,
            encoder = encoder,
            decoder = decoder
        )
        assertNotNull(jwtString)

        val jwtObject = JWT.decode(jwtString, appleJsonDecoder, decoder)

        assertNotNull(jwtObject)
        assertEquals("ES256", jwtObject?.header?.alg)
        assertEquals("keyId", jwtObject?.header?.kid)

        assertEquals(nowSeconds, jwtObject?.payload?.iat)
        assertEquals("teamId", jwtObject?.payload?.iss)
    }

    @Test
    fun testEncodeDecodeEC256() {

        val nowSeconds = Instant.now().epochSecond
        val expSeconds = nowSeconds + 3600

        // dummy key created in Apple dev console (without header & footer)
        val secret = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgofYVrV6I5TvcM1Gc\n" +
                "TxiNYa/K30VltjNMg0bupcr9VfagCgYIKoZIzj0DAQehRANCAATc/L5AvAOgsTM5\n" +
                "h07NRuxi4rU4JWVO7md6wTiJQS3SkMAiyzvSmMXCPf6x6tKyQeppM0jI7XWz+cjo\n" +
                "Q3raiQbh"

        val header = JWTAuthHeader(alg = Algorithm.ES256.name) // dummy key id

        val payload = CustomJWTAuthPayload("com.philjay.jwt", "test", "ISS", nowSeconds, expSeconds)

        val jwtString = JWT.token(Algorithm.ES256, header, payload, secret, jsonEncoder, encoder, decoder)
        assertNotNull(jwtString)

        val jwtObject = JWT.decode(jwtString, jsonDecoder, decoder)

        assertNotNull(jwtObject)
        assertEquals("ES256", jwtObject?.header?.alg)

        assertEquals("com.philjay.jwt", jwtObject?.payload?.sub)
        assertEquals("test", jwtObject?.payload?.name)
        assertEquals(nowSeconds, jwtObject?.payload?.iat)
        assertEquals(expSeconds, jwtObject?.payload?.exp)
        assertEquals("ISS", jwtObject?.payload?.iss)
    }

    @Test
    fun testEncodeDecodeRS256() {

        val nowSeconds = Instant.now().epochSecond
        val expSeconds = nowSeconds + 3600

        // dummy key
        val secret = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBANWfjyOAEf2mqkkn\n" +
                "31PtdAZK8HJry8T8RKoQg9CvyjP7VoFNSUP0iex21lZiC7SVG9T02I6GWb42EJ6p\n" +
                "NfLeVtCfBELmWdSbK8uYqUfKAfPONQycRYOsf1sP/pdW8Jwvf9dAqJyYEa+FiH0X\n" +
                "mPvBy2RCDnTCaRMu3QMr6YEm+LOzAgMBAAECgYB/8Em3xzH/Kdv+aETWbPX59tO+\n" +
                "k1S8qyEsgSuQxldhfnu2gOUKL+CSoDGKFrpP8qVyixlPcqM4ygR2IX1P8V0oB6Ia\n" +
                "GXucv9i3zockN0VCN2cR+1dkqkvEnBGjaRDHGCvkBXP6d59o5Qlxp5uoZ9/gcQf4\n" +
                "yOWj9/QmMt1Yi+l1AQJBAP4DXSOJdMLCj6gppwLr7STNkAYHFA4IfE+PIAiai8Vm\n" +
                "/CYQZAlhUpEiHgLtLPaVK24u55SyamboSKh2P4UeV/MCQQDXS1GQbLL+vVJhjL78\n" +
                "ex/6Gkr2bPqjHlFMGihoYo9OVPAffIBvhrVXhgNYJ76LFTDnVURbp12K5LwjLyQy\n" +
                "COVBAkAb1iaI1HF1PnkbxqTEzzIHzHcyEeiCuS9WUKsEBlu24FhVm4o69O1ldkWv\n" +
                "sGozA5nk00MRqpO6f04nF/5SCkc9AkBQFJL1Lolx2YfgAxMzJLUjOU5y1NxxeiBx\n" +
                "NzWahjaZw1xByfSYBzpCoPVzf+0PHMXA9mVj1iAkPqqAR9OlzMtBAkAdEvNs/xAK\n" +
                "l5VhkxmMDGiF+HX3tetU3tzkh9v4Z0pz9nVDWGDbIPjCjhc60z7SCpOwnlF0bf92\n" +
                "YTOPkpSdAGlO"

        val header = JWTAuthHeader(alg = Algorithm.RS256.name) // dummy key id

        val payload = CustomJWTAuthPayload("com.philjay.jwt", "test", "ISS", nowSeconds, expSeconds)

        val jwtString = JWT.token(Algorithm.RS256, header, payload, secret, jsonEncoder, encoder, decoder)
        assertNotNull(jwtString)

        val jwtObject = JWT.decode(jwtString, jsonDecoder, decoder)

        assertNotNull(jwtObject)
        assertEquals("RS256", jwtObject?.header?.alg)

        assertEquals("com.philjay.jwt", jwtObject?.payload?.sub)
        assertEquals("test", jwtObject?.payload?.name)
        assertEquals(nowSeconds, jwtObject?.payload?.iat)
        assertEquals(expSeconds, jwtObject?.payload?.exp)
        assertEquals("ISS", jwtObject?.payload?.iss)
    }
}