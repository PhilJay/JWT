# APNJWT
Kotlin JWT implementation (Json Web Token) as required by APNs (Apple Push Notification Service)


## Sample Usage

Create required encoders, decoders and JSON Mapper (e.g. Gson or equivalent). These are later used to properly encode or decode the token header and payload.

```kotlin
    val gson = GsonBuilder().create()

    val mapper = object : Mapper {
        override fun jsonString(header: JWTAuthHeader): String {
            return gson.toJson(header, JWTAuthHeader::class.java)
        }

        override fun jsonString(payload: JWTAuthPayload): String {
            return gson.toJson(payload, JWTAuthPayload::class.java)
        }
    }

    val encoder = object : Base64Encoder {
        override fun encode(bytes: ByteArray): String {
            return Base64.encodeBase64String(bytes)
        }
    }

    val decoder = object : Base64Decoder {
        override fun decode(bytes: ByteArray): ByteArray {
            return Base64.decodeBase64(bytes)
        }
    }
```

Create the token by providing the teamId, keyId and secret (private key excluding header and footer). The teamId can be obtained from the developer member center. The keyId can be obtained when you create your secret (private key).

```kotlin
    val token = JWT.token("teamId", "keyId", "secret", mapper, encoder, decoder)
```

Include the token in the authentication header when you make yor push notification request to APNs:

```
   'authentication' 'bearer $token'
```

