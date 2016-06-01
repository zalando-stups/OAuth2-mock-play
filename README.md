# OAuth2 Mock Play Server

## Intro

An implementation of an OAuth2 server designed for mocking/testing. Designed to
be very configurable by environment variables (via the use of Typesafe config)

## Todo
* Add an option to disable all consent screens (handy for tests that run
against the mock server)
* Write tests
* Create a docker image
* Improve documentation a bit more

## Running the server

### Dev Mode

* Load dependencies via `sbt update`
* Run via `sbt ~run`
* Go to [localhost:9000](http://localhost:9000)

### Prod Mode

Running:

* Run `sbt testProd`

Deployment:

* Produce executable via `sbt clean dist`
* Extract `unzip target/universal/OAuth2-mock-play-x.x.x.zip`
* Run `OAuth2-mock-play-x.x.x/bin/OAuth2-mock-play -Dhttp.port=9000`

## Docker Image
The project will be deployed to docker soon, stay tuned!

## License

The MIT License (MIT) Copyright © 2016 Zalando SE, https://tech.zalando.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
