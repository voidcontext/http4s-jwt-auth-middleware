---
layout: home
title: A JWT authentication middleware for http4s
section: home
---

# A JWT Auth middleware for http4s

## Installation

```scala
libraryDependencies += "com.gaborpihaj" %% "http4s-jwt-auth-middleware" % "0.2.0",
```

## Usage


```scala mdoc
import cats.effect.IO
import com.gaborpihaj.authmiddleware._
import org.http4s.server.AuthMiddleware
import pdi.jwt.JwtAlgorithm

case class UserClaim(userId: String)

implicit val userClaimDecoder: JwtContentDecoder[UserClaim] = (content: String) => Right(UserClaim(content))

val middleware: AuthMiddleware[IO, UserClaim] = JwtAuthMiddleware(JwtHmacStringKey("secret", Seq(JwtAlgorithm.HS512)))

```

