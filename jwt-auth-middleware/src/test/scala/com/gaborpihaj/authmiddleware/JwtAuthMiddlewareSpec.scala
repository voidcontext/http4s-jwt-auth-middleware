package com.gaborpihaj.authmiddleware

import cats.effect.IO
import io.circe.generic.auto._
import io.circe.parser
import org.http4s._
import org.http4s.headers.Authorization
import org.scalatest.Matchers
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

import java.security.{KeyPairGenerator}
import javax.crypto.{KeyGenerator, SecretKey}

class JwtAuthMiddlewareSpec extends Http4sSpec with Matchers {

  implicit val jwtDecoder: JwtContentDecoder[Claims] = new JwtContentDecoder[Claims] {
    override def decode(claims: String): Either[String, Claims] = parser.decode[Claims](claims).left.map(_.getMessage)
  }

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

  it should "work when a javax.crypto.SecretKey is provided" in {
    val secretKey: SecretKey = KeyGenerator.getInstance("AES").generateKey()

    val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
    val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.POST, uri"/some-endpoint", headers = headers)
    val middleware = JwtAuthMiddleware[IO, Claims](secretKey, Seq(JwtAlgorithm.HS512))

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Ok)
    response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
  }

  it should "work when a java.security.PrivateKey is provided" in {
    val keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair()

    val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), keyPair.getPrivate(), JwtAlgorithm.RS512)
    val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.POST, uri"/some-endpoint", headers = headers)
    val middleware = JwtAuthMiddleware[IO, Claims](keyPair.getPublic(), JwtAlgorithm.allRSA())

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Ok)
    response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
  }


}
