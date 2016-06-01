package models

import play.api.cache.CacheApi

case class PendingContentStoreCache(value: CacheApi) extends AnyVal

case class PendingConsentStore(state: String,
                               redirectUri: String,
                               responseType: ResponseType,
                               clientId: String,
                               scope: List[String])
