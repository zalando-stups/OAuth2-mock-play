package models

sealed class GrantType(val id: String)

object GrantType {
  case object AuthorizationCode extends GrantType("authorization_code")
  case object Password          extends GrantType("password")
  case object ClientCredentials extends GrantType("client_credentials")
}
