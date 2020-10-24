package com.gaborpihaj.authmiddleware

import cats.data.{Kleisli, OptionT}
import cats.{Applicative, Monad}
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Authorization
import org.http4s.server.AuthMiddleware
import org.http4s.{AuthScheme, AuthedRoutes, Credentials, Request}
import pdi.jwt.JwtClaim

/** Provides a JWT validation function that can be used with Http4s' AuthMiddleware.
 *
 * The module also provides a simplified interface to construct AuthMiddlewares.
 */
object JwtAuthMiddleware {

  /** Validates the JSON Web Token that is extracted from the Authorization header
   *
   * @param validationContext holds secrets, keys and encyrption/hashing algorithms used to validate the JWT's
   *                          signature
   * @return a validation function that can be used with Http4s' AuthMiddleware
   */
  def validateToken[F[_]: Monad, C](validationContext: JwtValidationContext)(
    implicit A: Applicative[F],
    D: JwtContentDecoder[C]
  ): Kleisli[F, Request[F], Either[Error, C]] =
    Kleisli { request =>
      val jwtDecoder = JwtValidationContext.decoder(validationContext)

      def parseCredentials(credentials: Credentials): Either[Error, JwtClaim] = credentials match {
        case Credentials.Token(AuthScheme.Bearer, token) =>
          jwtDecoder(token).toEither.left.map(_ => InvalidToken)
        case _ => Left[Error, JwtClaim](InvalidAuthHeader)
      }

      A.pure(
        for {
          authHeader <- request.headers.get(Authorization).toRight(InvalidAuthHeader)
          jwtClaim   <- parseCredentials(authHeader.credentials)
          content    <- D.decode(jwtClaim.content).left.map[Error](JwtContentDecoderError(_))
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
}
