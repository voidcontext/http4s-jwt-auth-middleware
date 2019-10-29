package com.gaborpihaj.authmiddleware

import cats.data.{Kleisli, OptionT}
import cats.{Applicative, Monad}
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Authorization
import org.http4s.server.AuthMiddleware
import org.http4s.{AuthScheme, AuthedRoutes, Credentials, Request}
import pdi.jwt.JwtClaim

import scala.util.{Failure, Success, Try}

object JwtAuthMiddleware {

  def validateToken[F[_]: Monad, C](validationContext: JwtValidationContext)(
    implicit A: Applicative[F],
    D: JwtContentDecoder[C]
  ): Kleisli[F, Request[F], Either[Error, C]] =
    Kleisli { request =>
      val jwtDecoder = JwtValidationContext.decoder(validationContext)

      def parseCredentials(credentials: Credentials): Either[Error, JwtClaim] = credentials match {
      case Credentials.Token(AuthScheme.Bearer, token) =>
        toEither(jwtDecoder(token)).left.map(_ => InvalidToken)
      case _ => Left[Error, JwtClaim](InvalidAuthHeader)
    }

    A.pure(
      for {
        authHeader <- request.headers.get(Authorization).toRight(InvalidAuthHeader).right
        jwtClaim   <- parseCredentials(authHeader.credentials).right
        content    <- D.decode(jwtClaim.content).left.map[Error](JwtContentDecoderError(_)).right
      } yield content
    )
  }

  def apply[F[_]: Monad, C](
    validationContext: JwtValidationContext
  )(implicit D: JwtContentDecoder[C]): AuthMiddleware[F, C] =
    AuthMiddleware(validateToken(validationContext), forbiddenOnFailure)

  def apply[F[_]: Monad, C, E](
    validationContext: JwtValidationContext,
    validate: Kleisli[F, Either[Error, C], Either[E, C]],
    onFailure: AuthedRoutes[E, F]
  )(implicit D: JwtContentDecoder[C]): AuthMiddleware[F, C] =
    AuthMiddleware(validateToken(validationContext).andThen(validate), onFailure)

  def forbiddenOnFailure[F[_]: Monad]: AuthedRoutes[Error, F] = {
    val dsl = new Http4sDsl[F] {}

    import dsl._
    Kleisli(_ => OptionT.liftF(Forbidden()))
  }

  // For Scala 2.11 compat
  private[this] def toEither[A](tryResult: Try[A]): Either[Throwable, A] = tryResult match {
    case Success(value)     => Right(value)
    case Failure(exception) => Left(exception)
  }
}
