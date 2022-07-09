package com.gaborpihaj.authmiddleware

import java.security.KeyPairGenerator
import javax.crypto.{KeyGenerator, SecretKey}

import cats.data.{Kleisli, NonEmptyList}
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import io.circe.generic.auto._
import io.circe.parser
import org.http4s._
import org.http4s.headers.{Authorization, Cookie}
import org.http4s.implicits._
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}

class JwtAuthMiddlewareSpec extends AnyWordSpec with Http4sSpec with Matchers {

  implicit val jwtDecoder: JwtContentDecoder[Claims] = new JwtContentDecoder[Claims] {
    override def decode(claims: String): Either[String, Claims] = parser.decode[Claims](claims).left.map(_.getMessage)
  }

  val secretKey = "secret-key"
  val hmacStringKey = JwtHmacStringKey(secretKey, Seq(JwtAlgorithm.HS512))

  val middleware = JwtAuthMiddleware.builder[IO, Claims](hmacStringKey).middleware

  val unauthenticateRequest = Request[IO](Method.GET, uri"/some-endpoint")

  val basicAuthHeader: Headers = Headers(Authorization(BasicCredentials("some-username", "some-password")))
  val basicAuthRequest = Request[IO](Method.GET, uri"/some-endpoint", headers = basicAuthHeader)

  val invalidToken = Jwt.encode(
    JwtClaim(
      content = """{"user-id": "some-user-id", "username": "some-user-name"}"""
    ),
    "wrong-secret",
    JwtAlgorithm.HS256
  )
  val invalidTokenAuthHeader: Headers = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, invalidToken)))
  val invalidTokenRequest = Request[IO](Method.GET, uri"/some-endpoint", headers = invalidTokenAuthHeader)

  val unparsebleToken = Jwt.encode(
    JwtClaim(
      content = """{invalid-json}"""
    ),
    secretKey,
    JwtAlgorithm.HS512
  )
  val unparsableTokenAuthHeader: Headers =
    Headers(Authorization(Credentials.Token(AuthScheme.Bearer, unparsebleToken)))
  val unparsableTokenRequest = Request[IO](Method.GET, uri"/some-endpoint", headers = unparsableTokenAuthHeader)

  val validToken = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
  val validAuthHeader = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, validToken)))
  val authorisedRequest = Request[IO](Method.GET, uri"/some-endpoint", headers = validAuthHeader)

  val validCookieHeader = Headers(Cookie(NonEmptyList.of(RequestCookie("test-auth-cookie", validToken))))
  val authorisedRequestWithCookie = Request[IO](Method.GET, uri"/some-endpoint", headers = validCookieHeader)

  val headerExtractor = List(JwtAuthMiddleware.extractTokenFromAuthHeader[IO] _)
  val cookieExtractor = List(JwtAuthMiddleware.extractTokenFromCookie[IO]("test-auth-cookie") _)

  "Validatetoken()" when {
    "used with AuthHeader extractor" should {
      "return MissingToken error when Authorization header is not present" in {
        val result = JwtAuthMiddleware
          .validateToken[IO, Claims](hmacStringKey, headerExtractor)
          .run(unauthenticateRequest)
          .unsafeRunSync()
        result should be(Left(MissingToken))
      }

      "return MissingToken error when authorization scheme is not Bearer" in {
        val result = JwtAuthMiddleware
          .validateToken[IO, Claims](hmacStringKey, headerExtractor)
          .run(basicAuthRequest)
          .unsafeRunSync()
        result should be(Left(MissingToken))
      }

      "return InvalidToken error when token is not valid" in {
        val result = JwtAuthMiddleware
          .validateToken[IO, Claims](hmacStringKey, headerExtractor)
          .run(invalidTokenRequest)
          .unsafeRunSync()
        result should be(Left(InvalidToken))
      }

      "return JwtContentDecoderError when JWTClaim's content is not decodable" in {
        val result = JwtAuthMiddleware
          .validateToken[IO, Claims](hmacStringKey, headerExtractor)
          .run(unparsableTokenRequest)
          .unsafeRunSync()
        result match {
          case Left(error) => error shouldBe an[JwtContentDecoderError]
          case _           => fail()
        }
      }

      "return the decoded content if there aren't any issues" in {
        val result = JwtAuthMiddleware
          .validateToken[IO, Claims](hmacStringKey, headerExtractor)
          .run(authorisedRequest)
          .unsafeRunSync()
        result should be(Right(Claims("some-user-id")))
      }
    }

    "used with Cookie extractor" should {
      "return MissingToken error when Authorization header is not present" in {
        val result = JwtAuthMiddleware
          .validateToken[IO, Claims](hmacStringKey, headerExtractor)
          .run(unauthenticateRequest)
          .unsafeRunSync()
        result should be(Left(MissingToken))
      }
      "return the decoded content if there aren't any issues" in {
        val result = JwtAuthMiddleware
          .validateToken[IO, Claims](hmacStringKey, cookieExtractor)
          .run(authorisedRequestWithCookie)
          .unsafeRunSync()
        result should be(Right(Claims("some-user-id")))
      }

    }
  }

  "JwtAuthMiddleware" should {
    "return 401 Forbidden when auth header is not present" in {
      val response = handleRequest(middleware, unauthenticateRequest).unsafeRunSync()
      response.status should be(Status.Unauthorized)
    }

    "return 401 Unauthorized when token is not valid and URL is not found" in {

      val token =
        Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), "some-other-secret", JwtAlgorithm.HS512)
      val headers = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
      val req = Request[IO](Method.GET, uri"/nonexistent", headers = headers)

      val response = handleRequest(middleware, req).unsafeRunSync()
      response.status should be(Status.Unauthorized)
    }

    "return 401 Unauthorized when the auth header is not using the bearer token scheme and URL is found" in {
      val response = handleRequest(middleware, basicAuthRequest).unsafeRunSync()
      response.status should be(Status.Unauthorized)
    }

    "return 401 Unauthorized when JWT token is not valid and URL is found" in {
      val token = Jwt.encode(
        JwtClaim(
          content = "some-content"
        ),
        "wrong-secret",
        JwtAlgorithm.HS512
      )
      val headers: Headers = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
      val req = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)

      val response = handleRequest(middleware, req).unsafeRunSync()
      response.status should be(Status.Unauthorized)
    }

    "return 401 Unauthorized when JWT algorithm is not matching and URL is found" in {
      val response = handleRequest(middleware, invalidTokenRequest).unsafeRunSync()
      response.status should be(Status.Unauthorized)
    }

    "return 200 when token is valid and URL is found" in {
      val response = handleRequest(middleware, authorisedRequest).unsafeRunSync()
      response.status should be(Status.Ok)
      response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
    }

    "return 200 when token is valid and provided in a cookie and URL is found" in {
      val m = JwtAuthMiddleware.builder[IO, Claims](hmacStringKey).expectCookieOnly("test-auth-cookie").middleware
      val response = handleRequest(m, authorisedRequestWithCookie).unsafeRunSync()
      response.status should be(Status.Ok)
      response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
    }

    "return 404 when token is valid but URL is not found" in {
      val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
      val headers = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
      val req = Request[IO](Method.GET, uri"/nonexistent", headers = headers)

      val response = handleRequest(middleware, req).unsafeRunSync()
      response.status should be(Status.NotFound)
    }

    "return 200 OK when a javax.crypto.SecretKey is provided and token is valid" in {
      val secretKey: SecretKey = KeyGenerator.getInstance("AES").generateKey()

      val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
      val headers = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
      val req = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)
      val middleware =
        JwtAuthMiddleware.builder[IO, Claims](JwtHmacSecretKey(secretKey, Seq(JwtAlgorithm.HS512))).middleware

      val response = handleRequest(middleware, req).unsafeRunSync()
      response.status should be(Status.Ok)
      response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
    }

    "return 200 OK when a java.security.PrivateKey is provided and token is valid" in {
      val keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair()

      val token =
        Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), keyPair.getPrivate(), JwtAlgorithm.RS512)
      val headers = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
      val req = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)
      val middleware =
        JwtAuthMiddleware.builder[IO, Claims](JwtPublicKey(keyPair.getPublic(), JwtAlgorithm.allRSA())).middleware

      val response = handleRequest(middleware, req).unsafeRunSync()
      response.status should be(Status.Ok)
      response.attemptAs[String].value.unsafeRunSync() should be(Right("some-user-id"))
    }

    "apply additional validation if provided" in {
      val secretKey = "secret-key"
      val hmacStringKey = JwtHmacStringKey(secretKey, Seq(JwtAlgorithm.HS512))

      val token = Jwt.encode(JwtClaim(content = """{"userId": "some-user-id"}"""), secretKey, JwtAlgorithm.HS512)
      val headers = Headers(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
      val req = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)

      val validation: Kleisli[IO, Claims, Either[Error, Claims]] = Kleisli(_ => IO.pure(Left(ExpiredToken)))

      val middleware = JwtAuthMiddleware.builder[IO, Claims](hmacStringKey).validate(validation).middleware

      val response = handleRequest(middleware, req).unsafeRunSync()
      response.status should be(Status.Unauthorized)
    }
  }
}
