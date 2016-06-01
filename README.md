# OAuth2 Mock Play Server

## Intro

An implementation of an OAuth2 server designed for mocking/testing. Designed to
be very configurable by environment variables (via the use of Typesafe config).

The project aims to be useful for people who are creating a web application that is gated by an OAuth
login, particularly in regards to testing and local development. Typically web applications would
have to explicitly code a flag to disable OAuth2 in their application, or they would have to use
a production OAuth2 server and have to deal with port forwarding/reverse proxying/generating fake certificates
to get redirect's working.

With the mock you simply run the server and configure your applications OAuth2 endpoints to the mock server. Its
also designed to be highly configurable via environment variables, so its easy to configure the mock to suite your
applications needs.

In the future (when the no consent screen toggle is implemented) it can also be used as a replacement for
creating mocks physically in the code when running tests, simply run the server and configure your web
application to point the mock OAuth2 server when running the tests.

The project is similar in design to [oauth2 provider](https://github.com/zalando-stups/mocks/tree/master/oauth2-provider),
however it aims to be much more configurable and also provides a completely implementation of OAuth2 spec rather
than some specific login flows

## Todo
* Add an option to disable all consent screens (handy for tests that run
against the mock server)
* Add some more really specific configuration (such as disabling `client_secret` checks
since not all OAuth2 servers use this)
* Write tests
* Create a docker image
* Improve documentation a bit more

## Running the server via Play

* Load dependencies via `sbt update`
* Run via `sbt ~run`
* Point your web application against [localhost:9000](http://localhost:9000)

Note that you may need to disable secure cookies in your web application for this to work, since the server
is running over standard HTTP rather than HTTPS

## Docker Image
The project will be deployed to docker soon, stay tuned!

## License

The MIT License (MIT) Copyright © 2016 Zalando SE, https://tech.zalando.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
