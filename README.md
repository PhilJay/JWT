[![Release](https://img.shields.io/github/release/PhilJay/APNJWT.svg?style=flat)](https://jitpack.io/#PhilJay/APNJWT)

# JWT
Kotlin JWT implementation (Json Web Token) as required by APNs (Apple Push Notification Service) or Sign in with Apple, for use on Kotlin powered backend servers. Eases the process of creating the token based on your credentials.

No other dependencies required.

## Dependency 

Add the following to your **build.gradle** file:
```groovy
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}

dependencies {
    implementation 'com.github.PhilJay:APNJWT:1.0.6'
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
    <artifactId>APNJWT</artifactId>
    <version>1.0.6</version>
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

Create the token by providing your teamId, keyId and secret (private key excluding header and footer). The teamId can be obtained from the developer member center. The keyId can be obtained when you create your secret (private key).

```kotlin
    val token = JWT.token("teamId", "keyId", "secret", jsonEncoder, encoder, decoder)

    // or...
    val header = JWTAuthHeader(...)
    val payload = JWTAuthPayload(...)
    val token = JWT.token(header, payload, "secret", jsonEncoder, encoder, decoder)
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
    val token: JWTToken<JWTAuthHeader, JWTAuthPayload>? = JWT.decode(tokenString, jsonDecoder, decoder)
    // conveniently access properties of the token...
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

For a detailed guide, please visit the [APNs documentation](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/APNSOverview.html#//apple_ref/doc/uid/TP40008194-CH8-SW1) page by Apple as well as the [verifying users](https://developer.apple.com/documentation/signinwithapplerestapi/verifying_a_user) and [generating tokens](https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens) pages for Sign in with Apple.

