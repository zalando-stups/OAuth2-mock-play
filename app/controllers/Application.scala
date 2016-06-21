package controllers

import java.time.LocalDateTime
import java.time.Duration
import java.util.concurrent._
import sun.misc.BASE64Decoder

import cats.data.Xor
import com.typesafe.config.{Config, ConfigException}
import models._
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ValueReader
import play.api.data.Forms._
import play.api.data._
import play.api.libs.json.Json.JsValueWrapper
import play.api.libs.json.{JsObject, JsString, JsValue, Json}
import play.api.mvc._
import scala.language.postfixOps
import scala.concurrent.ExecutionContext
import scala.concurrent.duration._

/** Application controller, handles authentication */
class Application(implicit val executionContext: ExecutionContext,
                  val pendingConsentStoreCache: PendingContentStoreCache,
                  val authorizeStoreCache: AuthorizeStoreCache,
                  val config: Config)
    extends Controller {

  /**
    * Find out if there is any extra scope data that we want to send to the client
    *
    * @param accessTokenResponse A constructed access token response
    * @param requestedUserScopes The scopes that the user is requesting
    * @return
    */
  private def generateAuthorizationResponse(
      accessTokenResponse: AccessTokenResponse,
      requestedUserScopes: List[String],
      maybeUid: Option[String]): JsValue = {

    val uidScope = maybeUid match {
      case Some(uid) =>
        Seq(ScopeData("uid", uid))
      case None =>
        Seq.empty
    }

    val mapData: Seq[(String, JsValueWrapper)] =
      (uidScope ++ customScopeData).filter { scopeData =>
        requestedUserScopes.contains(scopeData.scope) && {
          // Whitelist of keys we don't want to override
          !List("access_token",
                "expires_in",
                "scope",
                "grant_type",
                "token_type",
                "realm").contains(scopeData.scope)
        }
      }.flatMap {
        case scopeData =>
          Seq((scopeData.scope, JsString(scopeData.value): JsValueWrapper))
      }

    Json.toJson(accessTokenResponse) match {
      case j: JsObject => j ++ Json.obj(mapData: _*)
      case j => j
    }
  }

  def deliminatedReader(config: Config, path: String, typeString: String) = {
    val s = config.getString(path)
    val split = s.split(":")
    if (split.length == 2) {
      (split(0), split(1))
    } else {
      throw new ConfigException.WrongType(
          config.origin(), path, typeString, "String")
    }
  }

  private def decodeBasicAuth(auth: String): Option[(String, String)] = {
    lazy val basicSt = "basic "

    if (auth.length() < basicSt.length()) {
      return None
    }
    val basicReqSt = auth.substring(0, basicSt.length())
    if (basicReqSt.toLowerCase() != basicSt) {
      return None
    }
    val basicAuthSt = auth.replaceFirst(basicReqSt, "")
    //BESE64Decoder is not thread safe, don't make it a field of this object
    val decoder = new BASE64Decoder()
    val decodedAuthSt = new String(decoder.decodeBuffer(basicAuthSt), "UTF-8")
    val usernamePassword = decodedAuthSt.split(":")
    if (usernamePassword.length >= 2) {
      //account for ":" in passwords
      return Some((usernamePassword(0), usernamePassword.splitAt(1)._2.mkString(":")))
    }
    None
  }

  implicit val clientCredentialsValueReader =
    new ValueReader[ClientCredential] {
      def read(config: Config, path: String): ClientCredential = {
        ClientCredential.tupled(
            deliminatedReader(config, path, "models.ClientCredential"))
      }
    }

  implicit val userDetailsValueReader = new ValueReader[UserDetail] {
    def read(config: Config, path: String): UserDetail = {
      UserDetail.tupled(deliminatedReader(config, path, "models.UserDetail"))
    }
  }

  implicit val scopeDataReader = new ValueReader[ScopeData] {
    def read(config: Config, path: String): ScopeData = {
      ScopeData.tupled(deliminatedReader(config, path, "models.ScopeData"))
    }
  }

  lazy val scopeRequestDelimiter =
    config.as[String]("OAuth2.scope.requestDelimiter")
  lazy val serverScopes = config.as[List[String]]("OAuth2.scope.list")
  lazy val clients =
    config.as[List[ClientCredential]]("OAuth2.applicationCredentials")
  lazy val expiration = config.as[FiniteDuration]("OAuth2.expiration")
  lazy val users = config.as[List[UserDetail]]("OAuth2.users")
  lazy val realm = config.as[String]("OAuth2.realm")
  lazy val customScopeData =
    config.as[Seq[ScopeData]]("OAuth2.customScopeData")
  lazy val internalRedirectTimeout =
    config.as[FiniteDuration]("OAuth2.internalRedirectTimeout")
  lazy val pendingConsentTimeout =
    config.as[FiniteDuration]("OAuth2.pendingConsentTimeout")
  lazy val disableConsent = config.as[Boolean]("OAuth2.disableConsent")

  val accessTokenForm = Form(
    tuple(
      "grant_type" -> optional(text),
      "scope" -> optional(text),
      "username" -> optional(text),
      "password" -> optional(text),
      "code" -> optional(text),
      "client_id" -> optional(text),
      "client_secret" -> optional(text),
      "redirect_uri" -> optional(text)
    )
  )
  def accessToken = {
    Action {implicit request =>
      val (maybeGrantType: Option[String],
          maybeScope: Option[String],
          maybeUsername: Option[String],
          maybePassword: Option[String],
          maybeCode: Option[String],
          maybeClientId: Option[String],
          maybeClientSecret: Option[String],
          maybeRedirectUri: Option[String]) = accessTokenForm.bindFromRequest.get
      val auth = request.headers.get("authorization").flatMap(decodeBasicAuth)
      maybeGrantType match {
        case Some("authorization_code") =>
          val params = for {
            code <- Xor.fromOption(
                       maybeCode,
                       UnprocessableEntity(
                           views.Application.error("Missing code")))
            clientId <- Xor.fromOption(
                        maybeClientId orElse auth match {
                            case Some((clientId, clientSecret)) => Some(clientId)
                            case _ => None
                        },
                        UnprocessableEntity(views.Application.error(
                              "Missing client_id")))
            clientSecret <- Xor.fromOption(
                    maybeClientSecret orElse auth match {
                      case Some((clientId, clientSecret)) => Some(clientSecret)
                      case _ => None
                    },
                    UnprocessableEntity(views.Application.error(
                          "Missing client_secret")))
            redirectUri <- Xor.fromOption(
                              maybeRedirectUri,
                              UnprocessableEntity(views.Application.error(
                                      "Missing redirect_uri")))
            authorizeStore <- {
              for {
                retrieve <- Xor.fromOption(
                               authorizeStoreCache.value
                                 .get[AuthorizeStore](code),
                               Unauthorized(
                                   views.Application.error("Invalid Login")))
                authorizeStore <- {
                  retrieve match {
                    case a @ AuthorizeStore.Code(state,
                                                 clientIdStore,
                                                 redirectUriStore,
                                                 username,
                                                 scope) =>
                      if (clientIdStore == clientId &&
                          redirectUriStore == redirectUri) {
                        Xor.right(a)
                      } else {
                        Xor.left(Forbidden(
                                views.Application.error("Security error")))
                      }
                    case _ =>
                      Xor.left(InternalServerError(
                              views.Application.error("Internal Error")))
                  }
                }
              } yield authorizeStore
            }
          } yield (code, clientId, clientSecret, redirectUri, authorizeStore)

          params match {
            case Xor.Right(
                (code, clientId, clientSecret, redirectUri, authorizeStore)) =>
              val accessToken = java.util.UUID.randomUUID.toString
              val secondAuthorizeStore = AuthorizeStore.Token(
                  accessToken,
                  LocalDateTime.now().plusNanos(expiration.toNanos),
                  TokenType.Bearer,
                  authorizeStore.username,
                  realm,
                  authorizeStore.scope
              )

              authorizeStoreCache.value.remove(code)
              authorizeStoreCache.value.set(
                  accessToken, secondAuthorizeStore, expiration)

              val accessTokenResponse = AccessTokenResponse(
                  accessToken,
                  expiration,
                  authorizeStore.scope,
                  GrantType.AuthorizationCode,
                  realm,
                  TokenType.Bearer
              )

              Ok(
                  generateAuthorizationResponse(
                      accessTokenResponse,
                      authorizeStore.scope,
                      Option(authorizeStore.username)))

            case Xor.Left(error) =>
              error
          }

        case Some("client_credentials") =>
          val params = for {
            clientId <- Xor.fromOption(
                    maybeClientId orElse auth match {
                        case Some((clientId, clientSecret)) => Some(clientId)
                        case _ => None
                    },
                    UnprocessableEntity(
                        views.Application.error("Missing client_id")))
            clientSecret <- Xor.fromOption(
                    maybeClientSecret orElse auth match {
                      case Some((clientId, clientSecret)) => Some(clientSecret)
                      case _ => None
                    },
                    UnprocessableEntity(views.Application.error(
                            "Missing client_secret")))
            find <- Xor.fromOption(
                       clients.find(_.clientId == clientId),
                       UnprocessableEntity(
                           views.Application.error("Invalid client_id")))
            checkSecret <- {
              if (find.clientSecret == clientSecret) {
                Xor.right(clientId)
              } else {
                Xor.left(
                    Unauthorized(views.Application.error("Invalid details")))
              }
            }
          } yield clientId

          params match {
            case Xor.Right(clientId) =>
              val accessToken = java.util.UUID.randomUUID.toString

              val accessTokenResponse = AccessTokenResponse(
                  accessToken,
                  expiration,
                  List.empty,
                  GrantType.ClientCredentials,
                  realm,
                  TokenType.Bearer
              )

              Ok(Json.toJson(accessTokenResponse))

            case Xor.Left(error) =>
              error
          }

        case Some("password") =>
          val params = for {
            username <- Xor.fromOption(
                           maybeUsername,
                           UnprocessableEntity(
                               views.Application.error("Missing username")))
            password <- Xor.fromOption(
                           maybePassword,
                           UnprocessableEntity(
                               views.Application.error("Missing password")))
            clientId <- Xor.fromOption(
                      maybeClientId orElse auth match {
                          case Some((clientId, clientSecret)) => Some(clientId)
                          case _ => None
                      },
                      UnprocessableEntity(
                          views.Application.error("Missing client_id")))
            clientSecret <- Xor.fromOption(
                        maybeClientSecret orElse auth match {
                          case Some((clientId, clientSecret)) => Some(clientSecret)
                          case _ => None
                        },
                       UnprocessableEntity(views.Application.error(
                               "Missing client_id")))
            checkClientId <- {
              Xor.fromOption(clients.find(_.clientId == clientId),
                             UnprocessableEntity(
                                 views.Application.error("Invalid client_id")))
            }
            checkClientSecret <- {
              if (checkClientId.clientSecret == clientSecret) {
                Xor.right(clientId)
              } else {
                Xor.left(Unauthorized("Invalid client_secret"))
              }
            }
            findUser <- Xor.fromOption(users.find(_.username == username),
                                       UnprocessableEntity("Invalid User"))
            checkPassword <- {
              if (findUser.password == password) {
                Xor.right(username)
              } else {
                Xor.left(Unauthorized("Invalid Password"))
              }
            }
          } yield (username, password, clientId)

          params match {
            case Xor.Right((username, password, clientId)) =>
              val scopes = maybeScope
                .map(_.split(scopeRequestDelimiter).to[List])
                .getOrElse(List.empty)
              val accessToken = java.util.UUID.randomUUID.toString

              val authorizeStore = AuthorizeStore.Token(
                  accessToken,
                  LocalDateTime.now().plusNanos(expiration.toNanos),
                  TokenType.Bearer,
                  username,
                  realm,
                  scopes
              )

              authorizeStoreCache.value.set(
                  accessToken, authorizeStore, expiration)

              val accessTokenResponse = AccessTokenResponse(
                  accessToken,
                  expiration,
                  scopes,
                  GrantType.Password,
                  realm,
                  TokenType.Bearer
              )

              Ok(generateAuthorizationResponse(accessTokenResponse,
                                               authorizeStore.scope,
                                               Option(username)))

            case Xor.Left(error) => error
          }

        case Some(_) =>
          UnprocessableEntity(views.Application.error("Invalid grant_type"))

        case _ =>
          UnprocessableEntity(views.Application.error("Missing grant_type"))
      }
    }
  }

  def authorize(maybeState: Option[String],
                maybeRedirectUri: Option[String],
                maybeResponseType: Option[String],
                maybeClientId: Option[String],
                maybeScope: Option[String]) = {
    val params = for {
      state <- Xor.fromOption(
                  maybeState,
                  UnprocessableEntity(views.Application.error("Missing state"))
              )
      redirectUri <- Xor.fromOption(
                        maybeRedirectUri,
                        UnprocessableEntity(
                            views.Application.error("Missing redirect_uri")))
      responseType <- maybeResponseType match {
                       case Some("token") => Xor.right(ResponseType.Token)
                       case Some("code") => Xor.right(ResponseType.Code)
                       case Some(_) =>
                         Xor.left(UnprocessableEntity(views.Application.error(
                                     "Invalid response_type")))
                       case _ =>
                         Xor.left(UnprocessableEntity(views.Application.error(
                                     "Missing response_type")))
                     }
      clientId <- {
        for {
          clientId <- Xor.fromOption(
                         maybeClientId,
                         UnprocessableEntity(
                             views.Application.error("Missing client_id")))
          exists <- {
            if (clients.map(_.clientId).contains(clientId)) {
              Xor.Right(clientId)
            } else {
              Xor.Left(
                  UnprocessableEntity(
                      views.Application.error("Invalid client_id"))
              )
            }
          }
        } yield exists
      }
      requestedScopes <- {
        val requestedScopes = maybeScope.map { requestedScope =>
          requestedScope.split(scopeRequestDelimiter).to[List]
        }.getOrElse(List.empty)
        if (requestedScopes.forall { requestedScope =>
              serverScopes.contains(requestedScope)
            }) {
          Xor.Right(requestedScopes)
        } else {
          Xor.Left(UnprocessableEntity(
                  views.Application.error("Requested scope doesn't exist")))
        }
      }
    } yield {
      (state, redirectUri, responseType, clientId, requestedScopes)
    }

    Action {
      params match {
        case Xor.Left(error) =>
          error
        case Xor.Right(
            (state, redirectUri, responseType, clientId, requestedScopes)) =>
          if (disableConsent) {
            // Automatically authorize depending on the response type
            users.lift(0) match {
              case Some(user) =>
                responseType match {
                  case ResponseType.Code =>
                    import com.netaporter.uri.dsl._
                    val code = java.util.UUID.randomUUID().toString
                    val authorizeStore = AuthorizeStore.Code(
                      state,
                      clientId,
                      redirectUri,
                      user.username,
                      requestedScopes
                    )

                    authorizeStoreCache.value.set(
                      code, authorizeStore, internalRedirectTimeout)

                    val url = (redirectUri ?
                      ("code" -> code) ?
                      ("state" -> state)).toString()

                    Redirect(url, MOVED_PERMANENTLY)
                  case ResponseType.Token =>
                    import com.netaporter.uri.dsl._
                    val accessToken = java.util.UUID.randomUUID.toString
                    val authorizeStore = AuthorizeStore.Token(
                      accessToken,
                      LocalDateTime.now().plusNanos(expiration.toNanos),
                      TokenType.Bearer,
                      user.username,
                      realm,
                      requestedScopes
                    )

                    authorizeStoreCache.value.set(
                      accessToken, authorizeStore, internalRedirectTimeout)

                    val url = com.netaporter.uri.Uri
                      .parse(redirectUri)
                      .withFragment(
                        ("token" -> accessToken) ?
                          ("expires_in" -> expiration.toSeconds.toString) ?
                          ("token_type" -> TokenType.Bearer.id) ?
                          ("state" -> state)
                      )
                      .toString()

                    Redirect(url, MOVED_PERMANENTLY)
                }
              case None =>
                InternalServerError(views.Application.error("Internal Error"))
            }
          } else {
            val authorizeQuery = PendingConsentStore(
              state,
              redirectUri,
              responseType,
              clientId,
              requestedScopes
            )
            pendingConsentStoreCache.value.set(
              state, authorizeQuery, pendingConsentTimeout)

            Ok(views.Application.consent(
              requestedScopes, state, scopeRequestDelimiter))
          }
      }
    }
  }

  val stateForm = Form(
      mapping(
          "state" -> OptionalMapping(text)
      )(StateForm.apply)(StateForm.unapply)
  )

  def accept() = Action(parse.form(stateForm)) { implicit request =>
    val params = for {
      state <- Xor.fromOption(
                  request.body.state,
                  UnprocessableEntity(
                      views.Application.error("Unknown pending consent")))
      authorizationData <- {
        Xor.fromOption(
            pendingConsentStoreCache.value.get[PendingConsentStore](state),
            InternalServerError(views.Application.error("Internal Error")))
      }
    } yield (state, authorizationData)

    params match {
      case Xor.Right((state, authorizationData)) =>
        if (authorizationData.state != state) {
          Forbidden(views.Application.error("Security error"))
        } else {
          Ok(views.Application.login(state))
        }
      case Xor.Left(error) =>
        error
    }
  }

  val loginForm = Form(
      mapping(
          "username" -> nonEmptyText,
          "password" -> nonEmptyText,
          "state" -> nonEmptyText
      )(LoginForm.apply)(LoginForm.unapply)
  )

  def login() = Action(parse.form(loginForm)) { implicit request =>
    val params = for {
      userLogin <- {
        users.find(_.username == request.body.username) match {
          case Some(userDetail) =>
            if (userDetail.password == request.body.password) {
              Xor.right(request.body.username)
            } else {
              Xor.left(
                  Unauthorized(views.Application.error("Invalid Login"))
              )
            }
          case None =>
            Xor.left(Unauthorized(views.Application.error("Invalid Login")))
        }
      }
      pendingConsentStore <- Xor.fromOption(
                                pendingConsentStoreCache.value
                                  .get[PendingConsentStore](
                                    request.body.state),
                                Unauthorized(
                                    views.Application.error("Invalid Login"))
                            )
    } yield (userLogin, pendingConsentStore)

    params match {
      case Xor.Right((userLogin, pendingConsentStore)) =>
        import com.netaporter.uri.dsl._

        pendingConsentStore.responseType match {
          case ResponseType.Code =>
            val code = java.util.UUID.randomUUID().toString
            val authorizeStore = AuthorizeStore.Code(
                pendingConsentStore.state,
                pendingConsentStore.clientId,
                pendingConsentStore.redirectUri,
                request.body.username,
                pendingConsentStore.scope
            )

            authorizeStoreCache.value.set(
                code, authorizeStore, internalRedirectTimeout)

            val url = (pendingConsentStore.redirectUri ?
                ("code" -> code) ?
                ("state" -> pendingConsentStore.state)).toString()

            Redirect(url, MOVED_PERMANENTLY)
          case ResponseType.Token =>
            val accessToken = java.util.UUID.randomUUID.toString
            val authorizeStore = AuthorizeStore.Token(
                accessToken,
                LocalDateTime.now().plusNanos(expiration.toNanos),
                TokenType.Bearer,
                request.body.username,
                realm,
                pendingConsentStore.scope
            )

            authorizeStoreCache.value.set(
                accessToken, authorizeStore, internalRedirectTimeout)

            val url = com.netaporter.uri.Uri
              .parse(pendingConsentStore.redirectUri)
              .withFragment(
                  ("token" -> accessToken) ?
                  ("expires_in" -> expiration.toSeconds.toString) ?
                  ("token_type" -> TokenType.Bearer.id) ?
                  ("state" -> pendingConsentStore.state)
              )
              .toString()

            Redirect(url, MOVED_PERMANENTLY)
        }

      case Xor.Left(error) => error
    }
  }
}
