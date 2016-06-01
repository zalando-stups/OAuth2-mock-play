package models

import scala.concurrent.duration.FiniteDuration

case class AuthorizeResponse(accessToken: String,
                             expiresIn: FiniteDuration,
                             tokenType: String,
                             realm: String,
                             scope: List[String])
