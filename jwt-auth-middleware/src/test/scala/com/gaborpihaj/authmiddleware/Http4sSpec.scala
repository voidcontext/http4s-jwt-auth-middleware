package com.gaborpihaj.authmiddleware

import cats.effect.IO
import fs2.Stream
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.implicits._
import org.http4s.server.AuthMiddleware

trait Http4sSpec {
  def handleRequest(middleware: AuthMiddleware[IO, Claims], request: Request[IO]): IO[Response[IO]] = {
    implicit val entityEncoder: EntityEncoder[IO, Claims] = new EntityEncoder[IO, Claims] {
      override def toEntity(a: Claims): Entity[IO] = Entity(
        Stream.emits[IO, Byte](a.userId.getBytes),
        Option(a.userId.getBytes().length.toLong)
      )

      override def headers: Headers = Headers.empty
    }

    val route = AuthedRoutes.of[Claims, IO]({ case GET -> Root / "some-endpoint" as claims => Ok(claims) })

    middleware(route).orNotFound
      .run(request)
  }
}
