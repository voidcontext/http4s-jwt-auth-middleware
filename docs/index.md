---
layout: home
title: A JWT authentication middleware for http4s
section: home
---

# A JWT Auth middleware for http4s

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

case class UserClaim(userId: String)

val middleware: AuthMiddleware[IO, UserClaim] = JwtAuthMiddleware(JwtHmacStringKey("secret", Seq(JwtAlgorithm.HS512)))

```

