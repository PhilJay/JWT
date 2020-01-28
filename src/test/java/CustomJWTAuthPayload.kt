import com.philjay.jwt.JWTAuthPayload

class CustomJWTAuthPayload(val sub: String, val name: String, iss: String, iat: Long, val exp: Long): JWTAuthPayload(iss, iat)