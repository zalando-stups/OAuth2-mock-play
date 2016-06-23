package views

import scalatags.Text.all._
import scalatags.text.Frag

object Application {

  def error(message: String) = {
    scalatags.Text.tags.html(
        head(
            title := "Error"
        ),
        body(
            h1("Error"),
            p(message)
        )
    )
  }

  def consent(scopes: List[String],
              state: String,
              scopeDelimiter: String): Frag = {
    scalatags.Text.tags.html(
        head(
            title := "Consent"
        ),
        body(
            h1("Consent"),
            p("Application is requesting the following scopes, do you accept?"),
            ul(
                scopes.map(scope => li(scope))
            ),
            div(
                form(action := "/accept", method := "POST")(
                    input(name := "state", `type` := "hidden", value := state),
                    input(name := "scope",
                          `type` := "hidden",
                          value := scopes.mkString(scopeDelimiter)),
                    button(`type` := "submit")(
                        "Yes"
                    )
                ),
                form(action := "/decline", method := "POST")(
                    input(name := "state", `type` := "hidden", value := state),
                    button(`type` := "submit")(
                        "No"
                    )
                )
            )
        )
    )
  }

  def login(state: String) = {
    scalatags.Text.tags.html(
        head(
            title := "Login"
        ),
        body(
            h1("User"),
            p("Please login with your credentials"),
            div(
                form(action := "/login", method := "POST")(
                    input(name := "state", `type` := "hidden", value := state),
                    label(`for` := "username")("Username: "),
                    input(name := "username", `type` := "text"),
                    br,
                    label(`for` := "password")("Password: "),
                    input(name := "password", `type` := "password"),
                    br,
                    button(`type` := "submit")(
                        "Login"
                    )
                )
            )
        )
    )
  }
}
