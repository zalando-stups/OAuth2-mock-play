package models

import play.api.libs.json.{Json, Writes}

import scala.concurrent.duration.FiniteDuration

case class TokeninfoResponse(accessToken: String,
                             grantType: GrantType,
                             expiresIn: FiniteDuration,
                             tokenType: TokenType,
                             realm: String,
                             uid: String,
                             scope: List[String])

object TokeninfoResponse {
  implicit val tokeninfoResponseWrites: Writes[TokeninfoResponse] = Writes(
     (tokeninfoResponse: TokeninfoResponse) => Json.obj(
       "access_token" -> tokeninfoResponse.accessToken,
       "grant_type" -> tokeninfoResponse.grantType.id,
       "expires_in" -> tokeninfoResponse.expiresIn.toSeconds,
       "scope" -> tokeninfoResponse.scope,
       "realm" -> tokeninfoResponse.realm,
       "token_type" -> tokeninfoResponse.tokenType.id,
       "uid" -> tokeninfoResponse.uid
     )
   )
}
