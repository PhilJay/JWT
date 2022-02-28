[![Release](https://img.shields.io/github/release/PhilJay/JWT.svg?style=flat)](https://jitpack.io/#PhilJay/JWT)

# JWT
Lightweight Kotlin JWT implementation (Json Web Token) designed for **Apple**, as required by APNs (Apple Push Notification Service) or Sign in with Apple (including JWT verification via JWK), for use on Kotlin powered backend servers. Eases the process of creating & verifying the token based on your credentials.

No other dependencies required.

## Algorithms supported
 - ES256
 - RS256

## Dependency 

Add the following to your **build.gradle** file:
```groovy
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}

dependencies {
    implementation 'com.github.PhilJay:JWT:1.2.0'
}
```

Or add the following to your **pom.xml**:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.PhilJay</groupId>
    <artifactId>JWT</artifactId>
    <version>1.2.0</version>
</dependency>
```

## Creating JWT

Create required encoders, decoders and JSON Mapper (e.g. Gson or equivalent). These are later used to properly encode or decode the token header and payload.

```kotlin
    val gson = GsonBuilder().create()
 
    // generic JSON encoder
    val jsonEncoder = object : JsonEncoder<JWTAuthHeader, JWTAuthPayload> {
        override fun toJson(header: JWTAuthHeader): String {
            return gson.toJson(header, JWTAuthHeader::class.java)
        }
    
        override fun toJson(payload: JWTAuthPayload): String {
            return gson.toJson(payload, JWTAuthPayload::class.java)
        }
    }

    // Base64 encoder using apache commons
    private val encoder = object : Base64Encoder {
        override fun encodeURLSafe(bytes: ByteArray): String {
            return Base64.encodeBase64URLSafeString(bytes)
        }
    
        override fun encode(bytes: ByteArray): String {
            return Base64.encodeBase64String(bytes)
        }
    }

    // Base64 decoder using apache commons
    private val decoder = object : Base64Decoder {
        override fun decode(bytes: ByteArray): ByteArray {
            return Base64.decodeBase64(bytes)
        }
    
        override fun decode(string: String): ByteArray {
            return Base64.decodeBase64(string)
        }
    }
```

Create the Apple JWT token by providing your teamId, keyId and secret (private key excluding header and footer). The teamId can be obtained from the developer member center. The keyId can be obtained when you create your secret (private key).

```kotlin
    val token = JWT.tokenApple("teamId", "keyId", "secret", jsonEncoder, encoder, decoder)
```

Create any JWT token by providing the required algorithm, header, payload and secret (private key):

```kotlin
    val header = JWTAuthHeader(...)
    val payload = JWTAuthPayload(...)
    val token = JWT.token(Algorithm.ES256, header, payload, "secret", jsonEncoder, encoder, decoder)
```

## Decoding JWT

If you want to decode a JWT String, create a JSON decoder:

```kotlin
    private val jsonDecoder = object : JsonDecoder<JWTAuthHeader, JWTAuthPayload> {

        override fun headerFrom(json: String): JWTAuthHeader {
            return gson.fromJson(json, JWTAuthHeader::class.java)
        }

        override fun palyoadFrom(json: String): JWTAuthPayload {
            return gson.fromJson(json, JWTAuthPayload::class.java)
        }
    }
```

Use the json decoder to decode your token String:
```kotlin
    val tokenString = "ey..." // a valid JWT as a String
    val t: JWTToken<JWTAuthHeader, JWTAuthPayload>? = JWT.decode(tokenString, jsonDecoder, decoder)
    
    // conveniently access properties of the token...
    val issuer = t?.payload?.iss
```

## Verifying

In order to verify a JWT received from Sign in with Apple, securely transmit it to your backend, then [obtain a JWK (Json Web Key) from Apple](https://developer.apple.com/documentation/signinwithapplerestapi/fetch_apple_s_public_key_for_verifying_token_signature) and use it as a public key for verification: 

```kotlin
    val jwk: JWKObject = ... // fetch JWK (public key) from Apple endpoint
    val tokenString = "ey..." // the JWT to validate
    
    // turns JWK into RSA public key, returns true if validation is successful
    val valid = JWT.verify(tokenString, jwk, decoder) 
```

## Usage with APNs

Include the token in the authentication header when you make yor push notification request to APNs:

```
   'authentication' 'bearer $token'
```



If you are [sending pushes to iOS 13+ devices](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/sending_notification_requests_to_apns), also include the `apns-push-type` header:

```
   'apns-push-type' 'alert' // possible values are 'alert' or 'background'
```

## Documentation

For a detailed guide, please visit the [APNs documentation](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/APNSOverview.html#//apple_ref/doc/uid/TP40008194-CH8-SW1) page by Apple as well as the [verifying users](https://developer.apple.com/documentation/signinwithapplerestapi/verifying_a_user) and [generating tokens](https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens) pages for Sign in with Apple. [jwt.io](https://jwt.io) is a good page for "debugging" tokens.

