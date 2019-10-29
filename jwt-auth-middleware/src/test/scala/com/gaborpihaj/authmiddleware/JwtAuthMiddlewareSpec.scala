package com.gaborpihaj.authmiddleware

import cats.effect.IO
import cats.data.OptionT
import io.circe.generic.auto._
import io.circe.parser
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.Authorization
import org.scalatest.Matchers
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

import java.security.{KeyPairGenerator}
import javax.crypto.{KeyGenerator, SecretKey}
import cats.data.Kleisli

class JwtAuthMiddlewareSpec extends Http4sSpec with Matchers {


  implicit val jwtDecoder: JwtContentDecoder[Claims] = new JwtContentDecoder[Claims] {
    override def decode(claims: String): Either[String, Claims] = parser.decode[Claims](claims).left.map(_.getMessage)
  }

  val secretKey = "secret-key"
  val hmacStringKey = JwtHmacStringKey(secretKey, Seq(JwtAlgorithm.HS512))

  val middleware = JwtAuthMiddleware[IO, Claims](hmacStringKey)

  val unauthenticateRequest = Request[IO](Method.GET, uri"/some-endpoint")

  val basicAuthHeader: Headers = Headers.of(Authorization(BasicCredentials("some-username", "some-password")))
  val basicAuthRequest = Request[IO](Method.GET, uri"/some-endpoint", headers = basicAuthHeader)

  val invalidToken = Jwt.encode(
    JwtClaim(
      content = """{"user-id": "some-user-id", "username": "some-user-name"}"""
    ),
    "wrong-secret",
    JwtAlgorithm.HS256
  )
  val invalidTokenAuthHeader: Headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, invalidToken)))
  val invalidTokenRequest = Request[IO](Method.GET, uri"/some-endpoint", headers = invalidTokenAuthHeader)

  val unparsebleToken = Jwt.encode(
    JwtClaim(
      content = """{invalid-json}"""
    ),
    secretKey,
    JwtAlgorithm.HS512
  )
  val unparsableTokenAuthHeader: Headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, unparsebleToken)))
  val unparsableTokenRequest = Request[IO](Method.GET, uri"/some-endpoint", headers = unparsableTokenAuthHeader)

  val validToken = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
  val validAuthHeader = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, validToken)))
  val authorisedRequest = Request[IO](Method.GET, uri"/some-endpoint", headers = validAuthHeader)

  "Validatetoken()" should "return InvalidAuthHeader error when Authorization header is not present" in {
    val result = JwtAuthMiddleware.validateToken[IO, Claims](hmacStringKey).run(unauthenticateRequest).unsafeRunSync()
    result should be(Left(InvalidAuthHeader))
  }

  it should "return InvalidAuthHeader error when authorization scheme is not Bearer" in {
    val result = JwtAuthMiddleware.validateToken[IO, Claims](hmacStringKey).run(basicAuthRequest).unsafeRunSync()
    result should be(Left(InvalidAuthHeader))
  }

  it should "return InvalidToken error when token is not valid" in {
    val result = JwtAuthMiddleware.validateToken[IO, Claims](hmacStringKey).run(invalidTokenRequest).unsafeRunSync()
    result should be(Left(InvalidToken))
  }

  it should "return JwtContentDecoderError when JWTClaim's content is not decodable" in {
    val result = JwtAuthMiddleware.validateToken[IO, Claims](hmacStringKey).run(unparsableTokenRequest).unsafeRunSync()
    result match {
      case Left(error) => error shouldBe an[JwtContentDecoderError]
      case _ => fail()
    }
  }

  it should "return the decoded content if there aren't any issues" in {
    val result = JwtAuthMiddleware.validateToken[IO, Claims](hmacStringKey).run(authorisedRequest).unsafeRunSync()
    result should be(Right(Claims("some-user-id")))
  }

  "JwtAuthMiddleware" should "return 403 Forbidden when auth header is not present" in {
    val response = handleRequest(middleware, unauthenticateRequest).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }

  it should "return 403 Forbidden when token is not valid and URL is not found" in {

    val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), "some-other-secret", JwtAlgorithm.HS512)
    val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.GET, uri"/nonexistent", headers = headers)

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }

  it should "return 403 Forbidden when the auth header is not using the bearer token scheme and URL is found" in {
    val response = handleRequest(middleware, basicAuthRequest).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }

  it should "return 403 Forbidden when JWT token is not valid and URL is found" in {
    val token = Jwt.encode(
      JwtClaim(
        content = "some-content"
      ),
      "wrong-secret",
      JwtAlgorithm.HS512
    )
    val headers: Headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }

  it should "return 403 Forbidden when JWT algorithm is not matching and URL is found" in {
    val response = handleRequest(middleware, invalidTokenRequest).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }

  it should "return 200 when token is valid and URL is found" in {
    val response = handleRequest(middleware, authorisedRequest).unsafeRunSync()
    response.status should be(Status.Ok)
    response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
  }

  it should "return 404 when token is valid but URL is not found" in {
    val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
    val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.GET, uri"/nonexistent", headers = headers)

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.NotFound)
  }

  it should "return 200 OK when a javax.crypto.SecretKey is provided and token is valid" in {
    val secretKey: SecretKey = KeyGenerator.getInstance("AES").generateKey()

    val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
    val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)
    val middleware = JwtAuthMiddleware[IO, Claims](JwtHmacSecretKey(secretKey, Seq(JwtAlgorithm.HS512)))

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Ok)
    response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
  }

  it should "return 200 OK when a java.security.PrivateKey is provided and token is valid" in {
    val keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair()

    val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), keyPair.getPrivate(), JwtAlgorithm.RS512)
    val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)
    val middleware = JwtAuthMiddleware[IO, Claims](JwtPublicKey(keyPair.getPublic(), JwtAlgorithm.allRSA()))

    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Ok)
    response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
  }

  it should "apply additional validation if provided" in {
    val secretKey = "secret-key"
    val hmacStringKey = JwtHmacStringKey(secretKey, Seq(JwtAlgorithm.HS512))


    val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
    val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    val req = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)

    val validation: Kleisli[IO, Either[Error, Claims], Either[String, Claims]] = Kleisli { result => 
      IO.pure(result.left.map(_.toString).right.flatMap(_ => Left("Nope!")))
    }

    val onFailure: AuthedRoutes[String, IO] = Kleisli(req => OptionT.liftF(Forbidden(req.authInfo)))

    val middleware = JwtAuthMiddleware[IO, Claims, String](hmacStringKey, validation, onFailure)


    val response = handleRequest(middleware, req).unsafeRunSync()
    response.status should be(Status.Forbidden)
  }
}
