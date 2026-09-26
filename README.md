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

## Creating JWT

The private key is the content of the `.p8` file from the Apple developer console. The PEM header and footer are optional. Load it once with `Keys.privateKey(pem, Algorithm.ES256)` and reuse the `PrivateKey`.

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

The key is picked by the token's `kid`. Without a `kid`, every key that fits the algorithm is tried. The algorithm always has to fit the key, so a token cannot switch to another algorithm.

An `Invalid` result carries a `JWTVerificationError`: `MALFORMED`, `UNSUPPORTED_ALGORITHM`, `NO_MATCHING_KEY`, `INVALID_SIGNATURE`, `MISSING_EXPIRATION`, `EXPIRED`, `NOT_YET_VALID`, `ISSUED_IN_FUTURE`, `INVALID_ISSUER`, `INVALID_AUDIENCE` or `INVALID_NONCE`.

`aud` is read as a single string, as Apple sends it. Tokens with an array `aud` are rejected as `MALFORMED`.

Other helpers:

- `JWT.verifySignature(jwt, publicKey, algorithm)` and `JWT.verifySignature(jwt, jwk)` check only the signature, not the claims.
- `JWT.decode(jwt, jsonDecoder)` does not verify anything, so never use its result to authenticate a user.
- `Keys.privateKey(pem, algorithm)` and `Keys.publicKey(pem, algorithm)` read PKCS#8 and X.509 PEM keys.
- `JWKObject.fromPublicKey(key, algorithm, kid)` turns your own public key into a JWK, e.g. to publish a key set.

## Migrating from 1.x

- Remove the `Base64Encoder` / `Base64Decoder` and `charset` arguments. Base64url and UTF-8 are built in.
- `JWT.verify(jwt, jwk, decoder)` is now `JWT.verifySignature(jwt, jwk)`. For Sign in with Apple use `JWT.verifyApple`, which also checks the claims.
- ES256 signatures now use the JWS format (64 bytes R || S) instead of DER. Strict verifiers rejected the 1.x signatures.
- `JWKObject.toRSA` is now `toPublicKey` and supports EC keys. `toRSAString` was removed.
- RSA keys need at least 2048 bits. The header `alg` must match the signing algorithm.
- `decode` returns null for anything that is not a signed token with exactly three parts.
- Payload claims are nullable. `JWTAuthPayload` now also has `exp`, `nbf`, `aud`, `sub` and `jti`.

## Usage with APNs

Include the token in the authorization header of your push request:

```
authorization: bearer $token
apns-push-type: alert
```

## Documentation

For a detailed guide, please visit Apple's pages on [token based APNs authentication](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns), [verifying a user](https://developer.apple.com/documentation/signinwithapplerestapi/verifying_a_user) and [generating and validating tokens](https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens). [jwt.io](https://jwt.io) is a good page for "debugging" tokens.
