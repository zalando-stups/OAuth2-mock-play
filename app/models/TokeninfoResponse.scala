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
}//{'grant_type': 'authorization_code', 'cn': 'Melchior Moos', 'uid': 'mmoos',
//'refresh_token': 'fbdf289b-3af9-4387-9925-1c50bf1ba345',
//'realm': 'employees', 'access_token': '3141f882-69a9-45eb-873a-ccf9104ed42b',
//'expires_in': 3599, 'scope': ['uid', 'cn'], 'token_type': 'Bearer'}
