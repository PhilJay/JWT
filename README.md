[![Release](https://img.shields.io/github/release/PhilJay/JWT.svg?style=flat)](https://jitpack.io/#PhilJay/JWT)

# JWT
Lightweight Kotlin JWT implementation (Json Web Token) designed for **Apple**, as required by APNs (Apple Push Notification Service) or Sign in with Apple (including JWT verification via JWK), for use on Kotlin powered backend servers. Eases the process of creating & verifying the token based on your credentials.

No other dependencies required.

## Algorithms supported
 - ES256, ES384, ES512
 - RS256, RS384, RS512 (keys with at least 2048 bits)

`none` and HMAC algorithms are rejected.

## Dependency

Requires **Java 17**.

Add the following to your **build.gradle** file:
```groovy
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}

dependencies {
    implementation 'com.github.PhilJay:JWT:2.0.0'
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
    <version>2.0.0</version>
</dependency>
```

## JSON mapping

The library does not ship a JSON parser. Provide a JSON encoder and decoder with the library of your choice, e.g. Gson:

```kotlin
val gson = GsonBuilder().create()

val jsonEncoder = object : JsonEncoder<AppleJWTAuthHeader, JWTAuthPayload> {
    override fun toJson(header: AppleJWTAuthHeader): String = gson.toJson(header)
    override fun toJson(payload: JWTAuthPayload): String = gson.toJson(payload)
}

val jsonDecoder = object : JsonDecoder<JWTAuthHeader, AppleIdentityTokenPayload> {
    override fun headerFrom(json: String): JWTAuthHeader = gson.fromJson(json, JWTAuthHeader::class.java)
    override fun payloadFrom(json: String): AppleIdentityTokenPayload = gson.fromJson(json, AppleIdentityTokenPayload::class.java)
}
```

Configure your encoder to omit `null` values (Gson does this by default).

With Jackson (`jackson-module-kotlin`), omit `null` values and ignore unknown properties, because Apple adds fields such as `email_verified` and `auth_time`:

```kotlin
val mapper = jacksonObjectMapper()
    .setDefaultPropertyInclusion(JsonInclude.Include.NON_NULL)
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

val jsonEncoder = object : JsonEncoder<AppleJWTAuthHeader, JWTAuthPayload> {
    override fun toJson(header: AppleJWTAuthHeader): String = mapper.writeValueAsString(header)
    override fun toJson(payload: JWTAuthPayload): String = mapper.writeValueAsString(payload)
}

val jsonDecoder = object : JsonDecoder<JWTAuthHeader, AppleIdentityTokenPayload> {
    override fun headerFrom(json: String): JWTAuthHeader = mapper.readValue(json)
    override fun payloadFrom(json: String): AppleIdentityTokenPayload = mapper.readValue(json)
}
```

## Creating JWT

The private key is the content of the `.p8` file from the Apple developer console. The PEM header and footer are optional. Load it once and reuse the `PrivateKey`:

```kotlin
val privateKey = Keys.privateKey(File("AuthKey_KEYID12345.p8").readText(), Algorithm.ES256)
```

Keep the key out of your repository, e.g. load it from an environment variable or a secret store.

APNs token (valid for one hour, reuse it until then):

```kotlin
val token = JWT.tokenApple("teamId", "keyId", privateKey, jsonEncoder)
```

Client secret for the Sign in with Apple REST API:

```kotlin
val clientSecret = JWT.appleClientSecret("teamId", "keyId", "com.example.app", privateKey, jsonEncoder, expiresIn = Duration.ofDays(1))
```

Any other token:

```kotlin
val header = JWTAuthHeader(alg = "ES256", kid = "keyId")
val payload = JWTAuthPayload(iss = "issuer", iat = now, exp = now + 3600)
val token = JWT.token(Algorithm.ES256, header, payload, privateKey, jsonEncoder)
```

## Verifying Sign in with Apple

Fetch [Apple's public keys](https://appleid.apple.com/auth/keys) over HTTPS and parse them into a `JWKSet`. Cache them and refetch when verification fails with `NO_MATCHING_KEY`.

```kotlin
val jwkSet = gson.fromJson(responseBody, JWKSet::class.java)
```

Then verify the identity token sent by your app:

```kotlin
val result = JWT.verifyApple(identityToken, jwkSet.keys, clientIds = setOf("com.example.app"), jsonDecoder, nonce = expectedNonce)

when (result) {
    is JWTVerificationResult.Valid -> signIn(result.token.payload.sub)
    is JWTVerificationResult.Invalid -> reject(result.error)
}
```

This checks the signature, `exp`, `iat`, the issuer `https://appleid.apple.com`, that `aud` is one of your client ids and, if given, the nonce.

The nonce is compared exactly as given. If your app sent a SHA-256 hash of the nonce to Apple, pass that hash.

### Example: Sign in with Apple backend

A verifier that caches Apple's keys and refetches them when Apple rotates its keys. It refetches at most once per minute, so tokens with made-up `kid` values cannot flood Apple with requests.

```kotlin
class AppleSignIn(private val clientIds: Set<String>) {
    private val http = HttpClient.newHttpClient()
    @Volatile private var keys: List<JWKObject> = emptyList()
    @Volatile private var keysFetchedAt = Instant.EPOCH

    fun verify(identityToken: String, nonce: String): AppleIdentityTokenPayload? {
        var result = JWT.verifyApple(identityToken, keys, clientIds, jsonDecoder, nonce)
        if ((result as? JWTVerificationResult.Invalid)?.error == JWTVerificationError.NO_MATCHING_KEY && refreshKeys()) {
            result = JWT.verifyApple(identityToken, keys, clientIds, jsonDecoder, nonce)
        }
        return result.tokenOrNull()?.payload
    }

    @Synchronized
    private fun refreshKeys(): Boolean {
        if (Duration.between(keysFetchedAt, Instant.now()) < Duration.ofMinutes(1)) return false
        val request = HttpRequest.newBuilder(URI("https://appleid.apple.com/auth/keys")).build()
        val body = http.send(request, HttpResponse.BodyHandlers.ofString()).body()
        keys = gson.fromJson(body, JWKSet::class.java).keys
        keysFetchedAt = Instant.now()
        return true
    }
}

val appleSignIn = AppleSignIn(clientIds = setOf("com.example.app"))
val user = appleSignIn.verify(identityToken, nonce) ?: throw UnauthorizedException()
val appleUserId = user.sub // stable user id, use it to find or create the account
```

To get refresh tokens (or to revoke them later, which Apple requires on account deletion), exchange the authorization code from your app with a client secret:

```kotlin
val clientSecret = JWT.appleClientSecret("TEAMID1234", "KEYID12345", "com.example.app", privateKey, jsonEncoder)
val form = mapOf(
    "client_id" to "com.example.app",
    "client_secret" to clientSecret,
    "code" to authorizationCode,
    "grant_type" to "authorization_code"
).entries.joinToString("&") { "${it.key}=${URLEncoder.encode(it.value, UTF_8)}" }

val request = HttpRequest.newBuilder(URI("https://appleid.apple.com/auth/token"))
    .header("content-type", "application/x-www-form-urlencoded")
    .POST(HttpRequest.BodyPublishers.ofString(form))
    .build()
val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
// the response contains refresh_token and an id_token, which you can verify with appleSignIn.verify
```

## Verifying other tokens

```kotlin
val validation = JWTValidation(issuer = "https://issuer.example", audiences = setOf("my-client"))
val result = JWT.verify(tokenString, jwks, jsonDecoder, validation)
```

`JWTValidation` options:

- `issuer`: required `iss`, or `null` to accept any issuer.
- `audiences`: accepted `aud` values, or an empty set to accept any audience.
- `leewaySeconds`: allowed clock difference for `exp`, `nbf` and `iat` (default 60).
- `requireExpiration`: reject tokens without `exp` (default true).
- `maxTokenLength`: reject longer tokens before decoding them (default `JWT.MAX_TOKEN_LENGTH`, 16 KB).

The key is picked by the token's `kid`. Without a `kid`, every key that fits the algorithm is tried. The algorithm always has to fit the key, so a token cannot switch to another algorithm.

An `Invalid` result carries a `JWTVerificationError`: `TOO_LONG`, `MALFORMED`, `UNSUPPORTED_ALGORITHM`, `NO_MATCHING_KEY`, `INVALID_SIGNATURE`, `MISSING_EXPIRATION`, `EXPIRED`, `NOT_YET_VALID`, `ISSUED_IN_FUTURE`, `INVALID_ISSUER`, `INVALID_AUDIENCE` or `INVALID_NONCE`.

`aud` may be a single string (as Apple sends it) or an array. Read it with `payload.audiences()`. A token passes the audience check if one of its values is in `audiences`.

Other helpers:

- `JWT.verifySignature(jwt, publicKey, algorithm)` and `JWT.verifySignature(jwt, jwk)` check only the signature, not the claims.
- `JWT.decode(jwt, jsonDecoder)` does not verify anything, so never use its result to authenticate a user.
- `Keys.privateKey(pem, algorithm)` and `Keys.publicKey(pem, algorithm)` read PKCS#8 and X.509 PEM keys.
- `JWKObject.fromPublicKey(key, algorithm, kid)` turns your own public key into a JWK, e.g. to publish a key set.

## Issuing your own tokens

Add your own claims by extending `JWTAuthPayload`:

```kotlin
class SessionPayload(
    val role: String,
    iss: String,
    iat: Long,
    exp: Long,
    aud: String,
    sub: String
) : JWTAuthPayload(iss = iss, iat = iat, exp = exp, aud = aud, sub = sub)
```

`sessionEncoder` and `sessionDecoder` are JSON mappers for `SessionPayload`, built like the ones above. Sign with your private key and publish the public key as a key set, e.g. at `/.well-known/jwks.json`. The `kid` lets you rotate keys: publish the new key next to the old one before you switch.

```kotlin
val now = Instant.now().epochSecond
val payload = SessionPayload("admin", "https://api.example.com", now, now + 900, "my-app", "user-42")
val token = JWT.token(Algorithm.ES256, JWTAuthHeader("ES256", kid = "2026-09"), payload, privateKey, sessionEncoder)

val jwks = JWKSet(listOf(JWKObject.fromPublicKey(publicKey, Algorithm.ES256, kid = "2026-09")))
val jwksJson = gson.toJson(jwks)
```

Verify the token in any service that knows the key set:

```kotlin
val validation = JWTValidation(issuer = "https://api.example.com", audiences = setOf("my-app"))
val role = JWT.verify(token, jwks.keys, sessionDecoder, validation).tokenOrNull()?.payload?.role
```

## Migrating from 1.x

- Remove the `Base64Encoder` / `Base64Decoder` and `charset` arguments. Base64url and UTF-8 are built in.
- `JWT.verify(jwt, jwk, decoder)` is now `JWT.verifySignature(jwt, jwk)`. For Sign in with Apple use `JWT.verifyApple`, which also checks the claims.
- ES256 signatures now use the JWS format (64 bytes R || S) instead of DER. Strict verifiers rejected the 1.x signatures.
- `JWKObject.toRSA` is now `toPublicKey` and supports EC keys. `toRSAString` was removed.
- RSA keys need at least 2048 bits. The header `alg` must match the signing algorithm.
- `decode` returns null for anything that is not a signed token with exactly three parts.
- Payload claims are nullable. `JWTAuthPayload` now also has `exp`, `nbf`, `aud`, `sub` and `jti`. `aud` is a `String` or a `List<String>`.
- Tokens longer than 16 KB are rejected by default.

## Usage with APNs

APNs rejects tokens older than one hour and also rejects creating new tokens too often. Create one token and refresh it every 50 minutes:

```kotlin
class ApnsTokenProvider(private val teamId: String, private val keyId: String, private val privateKey: PrivateKey) {
    private var token: String? = null
    private var createdAt = Instant.EPOCH

    @Synchronized
    fun token(): String {
        val current = token
        if (current != null && Duration.between(createdAt, Instant.now()) < Duration.ofMinutes(50)) return current
        return JWT.tokenApple(teamId, keyId, privateKey, jsonEncoder).also {
            token = it
            createdAt = Instant.now()
        }
    }
}
```

Send the push over HTTP/2 with the token in the `authorization` header. Use `api.sandbox.push.apple.com` for development builds.

```kotlin
val tokens = ApnsTokenProvider("TEAMID1234", "KEYID12345", privateKey)
val http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build()

val request = HttpRequest.newBuilder(URI("https://api.push.apple.com/3/device/$deviceToken"))
    .header("authorization", "bearer ${tokens.token()}")
    .header("apns-topic", "com.example.app")
    .header("apns-push-type", "alert")
    .POST(HttpRequest.BodyPublishers.ofString("""{"aps":{"alert":"Hello"}}"""))
    .build()
val response = http.send(request, HttpResponse.BodyHandlers.ofString())
```

## Documentation

For a detailed guide, please visit Apple's pages on [token based APNs authentication](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns), [verifying a user](https://developer.apple.com/documentation/signinwithapplerestapi/verifying_a_user) and [generating and validating tokens](https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens). [jwt.io](https://jwt.io) is a good page for "debugging" tokens.
