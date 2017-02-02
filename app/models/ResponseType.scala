package models

sealed abstract class ResponseType(id: String)

object ResponseType {
  case object Token extends ResponseType("token")
  case object Code  extends ResponseType("code")
}
