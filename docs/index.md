---
layout: home
title: A JWT authentication middleware for http4s
section: home
---

# http4s-jwt-auth-middleware

A collection of utility functions to glue together Http4s and JWT-scala.

The library provides some data types to define the context for the JWT signature validation, this context
than can be injected into the middleware itself which will decode and validate the token.

## Installation

```scala
// the core package
libraryDependencies += "com.gaborpihaj" %% "http4s-jwt-auth-middleware" % "0.2.0",

// optional decoders 
libraryDependencies += "com.gaborpihaj" %% "http4s-jwt-auth-circe" % "0.2.0",

```

## Usage


```scala mdoc
import cats.effect.IO
import com.gaborpihaj.authmiddleware._
import com.gaborpihaj.jwtauth.circe._
import org.http4s.server.AuthMiddleware
import io.circe.generic.auto._
import pdi.jwt.JwtAlgorithm

val secret = "secret"
case class UserClaim(userId: String)

// Create the middleware
val middleware: AuthMiddleware[IO, UserClaim] = JwtAuthMiddleware(JwtHmacStringKey(secret, Seq(JwtAlgorithm.HS512)))

import org.http4s._
import org.http4s.headers.Authorization
import org.http4s.implicits._
import org.http4s.dsl.io._
import pdi.jwt.{Jwt, JwtClaim}

// Example request
val token = Jwt.encode(JwtClaim(content = """{"userId": "some-id"}"""), "secret", JwtAlgorithm.HS512)

val headers = Headers.of(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
val request = Request[IO](Method.GET, uri"/some-endpoint", headers = headers)

// Dummy route what will respond with the userId in the response body
val route = AuthedRoutes.of[UserClaim, IO]({ case GET -> Root / "some-endpoint" as claims => Ok(claims.userId) })

// Run the middleware
middleware(route).orNotFound.run(request).unsafeRunSync().attemptAs[String].value.unsafeRunSync()

```

