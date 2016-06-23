package models

sealed abstract class TokenType(val id: String)

object TokenType {
  case object Bearer extends TokenType("Bearer")
}
