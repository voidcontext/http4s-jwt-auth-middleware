package com.gaborpihaj.authmiddleware

import cats.effect.IO
import io.circe.generic.auto._
import io.circe.parser.decode
import org.http4s._
import org.http4s.headers.Authorization
import org.scalatest.Matchers
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

class JwtAuthMiddlewareSpec extends Http4sSpec with Matchers {

  implicit val jwtDecoder: JwtContentDecoder[Claims] = (claims: String) => decode[Claims](claims).left.map(_.getMessage)

  val secretKey = "secret-key"
  val middleware = JwtAuthMiddleware[IO, Claims](secretKey, Seq(JwtAlgorithm.HS512))

  "JwtAuthMiddleware" should "return error when auth header is nor present" in {
    val req = Request[IO](Method.POST, uri"/some-endpoint")

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }

  it should "return the user claim when the header is valid" in {
    val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
    val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.POST, uri"/some-endpoint", headers = headers)

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Ok)
    response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
  }

  it should "return an error when the auth header is not using the bearer token scheme" in {
    val headers: Headers = Headers.of(Authorization(BasicCredentials("some-username", "some-password")))
    val req = Request[IO](Method.POST, uri"/some-endpoint", headers = headers)

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }

  it should "return an error when JWT token is not valid" in {
    val token = Jwt.encode(
      JwtClaim(
        content = "some-content"
      ),
      "wrong-secret",
      JwtAlgorithm.HS512
    )
    val headers: Headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.POST, uri"/some-endpoint", headers = headers)

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }

  it should "return an error when JWT algorithm is not matching" in {
    val token = Jwt.encode(
      JwtClaim(
        content = """{"user-id": "some-user-id", "username": "some-user-name"}"""
      ),
      "wrong-secret",
      JwtAlgorithm.HS256
    )
    val headers: Headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.POST, uri"/some-endpoint", headers = headers)

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }
}
