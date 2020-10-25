package com.gaborpihaj.authmiddleware

import cats.data.{Kleisli, OptionT}
import cats.{Applicative, Monad}
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Authorization
import org.http4s.server.AuthMiddleware
import org.http4s.{AuthScheme, AuthedRoutes, Credentials, Request}
import pdi.jwt.JwtClaim
import cats.syntax.eq._
import cats.instances.string._

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
  def validateToken[F[_]: Monad, C](
    validationContext: JwtValidationContext,
    tokenExtractors: List[Request[F] => Either[Error, String]]
  )(
    implicit D: JwtContentDecoder[C]
  ): Kleisli[F, Request[F], Either[Error, C]] =
    Kleisli { request =>
      val jwtDecoder = JwtValidationContext.decoder(validationContext)

      def validateToken(token: String): Either[Error, JwtClaim] =
        jwtDecoder(token).toEither.left.map(_ => InvalidToken)

      def extractFirst(req: Request[F]): Either[Error, String] =
        tokenExtractors
          .collectFirst {
            case e if e(req).isRight => e(req)
          }
          .getOrElse(Left(MissingToken))

      Applicative[F].pure(
        for {
          token    <- extractFirst(request)
          jwtClaim <- validateToken(token)
          content  <- D.decode(jwtClaim.content).left.map[Error](JwtContentDecoderError(_))
        } yield content
      )
    }

  def fromAuthHeader[F[_]: Monad, C](
    validationContext: JwtValidationContext
  )(implicit D: JwtContentDecoder[C]): AuthMiddleware[F, C] =
    AuthMiddleware(validateToken(validationContext, List(extractTokenFromAuthHeader[F] _)), forbiddenOnFailure)

  def fromAuthHeader[F[_]: Monad, C, E](
    validationContext: JwtValidationContext,
    validate: Kleisli[F, Either[Error, C], Either[E, C]],
    onFailure: AuthedRoutes[E, F]
  )(implicit D: JwtContentDecoder[C]): AuthMiddleware[F, C] =
    AuthMiddleware(validateToken(validationContext, List(extractTokenFromAuthHeader[F] _)).andThen(validate), onFailure)

  def fromCookie[F[_]: Monad, C](
    name: String,
    validationContext: JwtValidationContext
  )(implicit D: JwtContentDecoder[C]): AuthMiddleware[F, C] =
    AuthMiddleware(validateToken(validationContext, List(extractTokenFromCookie[F](name))), forbiddenOnFailure)

  def fromAuthHeader[F[_]: Monad, C, E](
    name: String,
    validationContext: JwtValidationContext,
    validate: Kleisli[F, Either[Error, C], Either[E, C]],
    onFailure: AuthedRoutes[E, F]
  )(implicit D: JwtContentDecoder[C]): AuthMiddleware[F, C] =
    AuthMiddleware(
      validateToken(validationContext, List(extractTokenFromCookie[F](name) _)).andThen(validate),
      onFailure
    )

  def apply[F[_]: Monad, C](
    name: String,
    validationContext: JwtValidationContext
  )(implicit D: JwtContentDecoder[C]): AuthMiddleware[F, C] =
    AuthMiddleware(
      validateToken(validationContext, List(extractTokenFromAuthHeader[F] _, extractTokenFromCookie[F](name))),
      forbiddenOnFailure
    )

  def apply[F[_]: Monad, C, E](
    name: String,
    validationContext: JwtValidationContext,
    validate: Kleisli[F, Either[Error, C], Either[E, C]],
    onFailure: AuthedRoutes[E, F]
  )(implicit D: JwtContentDecoder[C]): AuthMiddleware[F, C] =
    AuthMiddleware(
      validateToken(validationContext, List(extractTokenFromAuthHeader[F] _, extractTokenFromCookie[F](name) _))
        .andThen(validate),
      onFailure
    )

  def forbiddenOnFailure[F[_]: Monad]: AuthedRoutes[Error, F] = {
    val dsl = new Http4sDsl[F] {}

    import dsl._
    Kleisli(_ => OptionT.liftF(Forbidden()))
  }

  private[authmiddleware] def extractTokenFromAuthHeader[F[_]](req: Request[F]): Either[Error, String] =
    req.headers
      .get(Authorization)
      .flatMap(
        _.credentials match {
          case Credentials.Token(AuthScheme.Bearer, token) => Option(token)
          case _                                           => None
        }
      )
      .toRight(InvalidAuthHeader)

  private[authmiddleware] def extractTokenFromCookie[F[_]](name: String)(req: Request[F]): Either[Error, String] =
    req.cookies
      .find(_.name === name)
      .map(_.content)
      .toRight(MissingToken)

}
