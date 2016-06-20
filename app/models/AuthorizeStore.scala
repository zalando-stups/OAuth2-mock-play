package models

import java.time.LocalDateTime
import play.api.cache.CacheApi

case class AuthorizeStoreCache(value: CacheApi) extends AnyVal


sealed abstract class AuthorizeStore

object AuthorizeStore {
  case class Token(accessToken: String,
                   expirationDate: LocalDateTime,
                   tokenType: TokenType,
                   grantType: GrantType,
                   uid: String,
                   realm: String,
                   scope: List[String])
      extends AuthorizeStore

  case class Code(state: String,
                  clientId: String,
                  redirectUri: String,
                  username: String,
                  scope: List[String]) extends AuthorizeStore
}
