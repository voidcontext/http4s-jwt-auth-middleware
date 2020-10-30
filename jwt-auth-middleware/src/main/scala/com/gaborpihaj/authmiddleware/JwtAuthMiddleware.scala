package com.gaborpihaj.authmiddleware

import cats.data.{Kleisli, OptionT}
import cats.instances.string._
import cats.syntax.eq._
import cats.syntax.traverse._
import cats.{Applicative, Monad, Traverse}
import org.http4s._
import org.http4s.headers.Authorization
import org.http4s.server.AuthMiddleware
import pdi.jwt.JwtClaim

/**
 * Provides a JWT validation function that can be used with Http4s' AuthMiddleware.
 *
 * The module also provides a simplified interface to construct AuthMiddlewares.
 */
object JwtAuthMiddleware {

  /**
   * Validates the JSON Web Token that is extracted from the Authorization header
   *
   * @param validationContext holds secrets, keys and encyrption/hashing algorithms used to validate the JWT's
   *                          signature
   * @return a validation function that can be used with Http4s' AuthMiddleware
   */
  def validateToken[F[_]: Monad, C: JwtContentDecoder](
    validationContext: JwtValidationContext,
    tokenExtractors: List[Request[F] => Either[Error, String]]
  ): Kleisli[F, Request[F], Either[Error, C]] =
    Kleisli { request =>
      val jwtDecoder = JwtValidationContext.decoder(validationContext)

      def validateToken(token: String): Either[Error, JwtClaim] =
        jwtDecoder(token).toEither.left.map(_ => InvalidToken)

      def extractFirst(req: Request[F]): Either[Error, String] =
        tokenExtractors.collectFirst {
          case e if e(req).isRight => e(req)
        }
          .getOrElse(Left(MissingToken))

      Applicative[F].pure(
        for {
          token    <- extractFirst(request)
          jwtClaim <- validateToken(token)
          content  <- JwtContentDecoder[C].decode(jwtClaim.content).left.map[Error](JwtContentDecoderError(_))
        } yield content
      )
    }

  def builder[F[_]: Monad, C: JwtContentDecoder](
    validationContext: JwtValidationContext
  ): JwtAuthMiddlewareBuilder[F, C, Error] =
    JwtAuthMiddlewareBuilder(validationContext)

  trait JwtAuthMiddlewareBuilder[F[_], C, E] {
    def expectCookieOnly(name: String): JwtAuthMiddlewareBuilder[F, C, E]
    def allowCookie(name: String): JwtAuthMiddlewareBuilder[F, C, E]
    def recover(f: Kleisli[F, Either[E, C], Either[E, C]]): JwtAuthMiddlewareBuilder[F, C, E]
    def validate(f: Kleisli[F, C, Either[E, C]]): JwtAuthMiddlewareBuilder[F, C, E]
    def middleware: AuthMiddleware[F, C]
  }

  object JwtAuthMiddlewareBuilder {
    private[this] case class Builder[F[_], C](
      validationContext: JwtValidationContext,
      validate: Kleisli[F, Either[Error, C], Either[Error, C]],
      onFailure: AuthedRoutes[Error, F],
      extractors: List[Request[F] => Either[Error, String]]
    )

    def apply[F[_]: Monad, C: JwtContentDecoder](
      validationContext: JwtValidationContext
    ): JwtAuthMiddlewareBuilder[F, C, Error] =
      apply(
        Builder(
          validationContext = validationContext,
          validate = liftG(Kleisli[F, C, Either[Error, C]](c => Applicative[F].pure(Right(c)))),
          onFailure = Kleisli[OptionT[F, *], AuthedRequest[F, Error], Response[F]](_ =>
            OptionT.liftF(Applicative[F].pure(Response(Status.Unauthorized)))
          ),
          extractors = List(extractTokenFromAuthHeader[F] _)
        )
      )

    private[this] def liftG[F[_]: Applicative, G[_]: Monad: Traverse, T, S](
      k: Kleisli[F, T, G[S]]
    ): Kleisli[F, G[T], G[S]] =
      Kleisli(_.flatTraverse(k.run))

    private[this] def apply[F[_]: Monad, C: JwtContentDecoder](
      builder: Builder[F, C]
    ): JwtAuthMiddlewareBuilder[F, C, Error] =
      new JwtAuthMiddlewareBuilder[F, C, Error] {

        def expectCookieOnly(name: String): JwtAuthMiddlewareBuilder[F, C, Error] =
          apply(builder.copy(extractors = List(extractTokenFromCookie[F](name) _)))

        def allowCookie(name: String): JwtAuthMiddlewareBuilder[F, C, Error] =
          apply(builder.copy(extractors = List(extractTokenFromAuthHeader[F] _, extractTokenFromCookie[F](name) _)))

        def validate(f: Kleisli[F, C, Either[Error, C]]): JwtAuthMiddlewareBuilder[F, C, Error] =
          apply(builder.copy(validate = liftG(f)))

        def recover(f: Kleisli[F, Either[Error, C], Either[Error, C]]): JwtAuthMiddlewareBuilder[F, C, Error] =
          apply(builder.copy(validate = f))

        def middleware: AuthMiddleware[F, C] =
          AuthMiddleware(
            validateToken(builder.validationContext, builder.extractors).andThen(builder.validate),
            builder.onFailure
          )
      }
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
