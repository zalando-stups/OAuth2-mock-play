package models

import play.api.libs.json.{Json, Writes}

import scala.concurrent.duration.FiniteDuration

case class AccessTokenResponse(accessToken: String,
                               expiresIn: FiniteDuration,
                               scope: List[String],
                               grantType: GrantType,
                               realm: String,
                               tokenType: TokenType)

object AccessTokenResponse {
  implicit val accessTokenResponseWrites: Writes[AccessTokenResponse] = Writes(
    (accessTokenResponse: AccessTokenResponse) =>
      Json.obj(
        "access_token" -> accessTokenResponse.accessToken,
        "expires_in"   -> accessTokenResponse.expiresIn.toSeconds,
        "scope"        -> accessTokenResponse.scope,
        "grant_type"   -> accessTokenResponse.grantType.id,
        "token_type"   -> accessTokenResponse.tokenType.id,
        "realm"        -> accessTokenResponse.realm
    ))
}
