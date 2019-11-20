---
layout: docs
title: Step by step example
---

# Step by step example

First of all the necessary packages need to be imported:


```scala
import cats.effect.IO
import com.gaborpihaj.authmiddleware._  // For the helper function and the validation context
import com.gaborpihaj.jwtauth.circe._   // For automatic circe based Decoder derivation
import org.http4s.server.AuthMiddleware
import io.circe.generic.auto._          // For automatic circe based Decoder derivation
import pdi.jwt.JwtAlgorithm
```


A representation of the user claims must be defined, this representation must be a subset of the JWT data payload.

```
case class UserClaim(userId: String)
```

```
val secret = "secret"
case class UserClaim(userId: String)

// Create the middleware
val middleware: AuthMiddleware[IO, UserClaim] = JwtAuthMiddleware(JwtHmacStringKey(secret, Seq(JwtAlgorithm.HS512)))

```
