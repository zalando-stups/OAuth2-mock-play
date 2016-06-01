import play.api.http.{ContentTypeOf, ContentTypes, Writeable}
import play.api.mvc.Codec

package object controllers {
  // Allows us to automatically render a Result of type [[scalatags.Text.Frag]]

  implicit def scalaTagsContentType(
      implicit codec: Codec): ContentTypeOf[scalatags.Text.Frag] = {
    ContentTypeOf[scalatags.Text.Frag](Some(ContentTypes.HTML))
  }

  implicit def scalaTagsWritable(
      implicit codec: Codec): Writeable[scalatags.Text.Frag] = {
    Writeable(frag => codec.encode(frag.render))
  }
}
