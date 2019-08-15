package com.gaborpihaj.authmiddleware

import cats.data.{Kleisli, OptionT}
import cats.syntax.applicative._
import cats.{Applicative, Monad}
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Authorization
import org.http4s.server.AuthMiddleware
import org.http4s.{AuthScheme, AuthedRoutes, Credentials, Request}
import pdi.jwt.algorithms.JwtHmacAlgorithm
import pdi.jwt.{Jwt, JwtClaim}

import scala.util.{Failure, Success, Try}

object JwtAuthMiddleware {
  def apply[F[_]: Monad, C](secretKey: String, jwtAlgorithms: Seq[JwtHmacAlgorithm])(
    implicit D: JwtContentDecoder[C]
  ): AuthMiddleware[F, C] =
    AuthMiddleware(validateJWTToken(token => Jwt.decode(token, secretKey, jwtAlgorithms)), onFailure)

  private[this] def onFailure[F[_]: Monad]: AuthedRoutes[String, F] = {
    val dsl = new Http4sDsl[F] {}

    import dsl._
    Kleisli(req => OptionT.liftF(Forbidden(req.authInfo)))
  }

  private[this] def validateJWTToken[F[_]: Applicative, E, C](jwtDecoder: String => Try[JwtClaim])()(
    implicit D: JwtContentDecoder[C]
  ): Kleisli[F, Request[F], Either[String, C]] = Kleisli { request =>
    def parseCredentials(credentials: Credentials): Either[String, JwtClaim] = credentials match {
      case Credentials.Token(AuthScheme.Bearer, token) =>
        toEither(jwtDecoder(token)).left.map(_ => "JWT Token invalid")
      case _ => Left[String, JwtClaim]("Bearer token authorization scheme is required")
    }

    val errorMessageOrUserClaim = for {
      authHeader <- request.headers.get(Authorization).toRight("Couldn't find Authorization header").right
      jwtClaim   <- parseCredentials(authHeader.credentials).right
      content    <- D.decode(jwtClaim.content).right
    } yield content

    errorMessageOrUserClaim.pure[F]
  }

  // For Scala 2.11 compat
  private[this] def toEither[A](tryResult: Try[A]): Either[Throwable, A] = tryResult match {
    case Success(value)     => Right(value)
    case Failure(exception) => Left(exception)
  }
}
