# OAuth2 Mock Play Server

OAuth2 Mock Play Server is an implementation of an OAuth2 server for mocking/testing. It's designed to be configurable by environment variables (by use of the Typesafe config), so it's easy to configure the mock to suite your application's needs. With OAuth2 Mock Play Server, all you have to do is run the server and configure your application's OAuth2 endpoints to the mock server. 

##Project Intro
OAuth2 Mock Play Server exists out of necessity: The project author searched for an easily configurable, open-source OAuth2 mock server that supported all of the different login flows specified by the OAuth2 specification, and didn't find one. With that in mind, you might also find this project useful, especially if you're creating a web application gated by an OAuth login and need testing and local development support. Typically, you have to explicitly code a flag to disable OAuth2 in your application, or use a production OAuth2 server and deal with port forwarding, reverse proxying, and generating fake certificates to get redirects working.

You can also use OAuth2 Mock Play Server as a replacement for creating mocks physically in your code while running tests.
First, set `OAUTH2_DISABLE_CONSENT=true`. Then run the server and configure your web application to point the mock OAuth2 server while your tests run.

## To-Do
- [x] Add an option to disable all consent screens (handy for tests that run against the mock server)
- [ ] Add some very specific configurations—for example, disabling `client_secret` checks (not all OAuth2 servers use this)
- [ ] Write tests
- [x] Create a Docker image
- [ ] Improve documentation
- [ ] Add a Swagger spec for documentation
- [ ] Add logging

Community contributions are welcome: Just file an issue describing the contribution you'd like to make.

## Running the Server via Play

* Load dependencies via `sbt update`
* Run via `sbt ~run`
* Point your web application OAuth2 endpoints against [localhost:9000](http://localhost:9000). See
[routes](https://github.com/zalando/OAuth2-mock-play/blob/master/conf/routes) for info on the routes and
[application.conf](https://github.com/zalando/OAuth2-mock-play/blob/master/conf/application.conf) for guidance on how the
configuration works

Note that you might need to disable secure cookies in your web application for this to work, because the server
is running over standard HTTP rather than HTTPS.

## Docker Image

The project is currently deployed via the Zalando open source write endpoint
`registry-write.opensource.zalan.do/bteam/oauth2-mock-play:1.0.2`. However, the read/pull endpoint is without `-write`— namely, `registry.opensource.zalan.do/bteam/oauth2-mock-play:1.0.2`.

To run the Docker image, do:

```sh
docker run -it -p 9000:9000 registry.opensource.zalan.do/bteam/oauth2-mock-play:1.0.2
```

## License

The MIT License (MIT) Copyright © 2016 Zalando SE, https://tech.zalando.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
