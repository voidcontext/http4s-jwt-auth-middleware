package com.gaborpihaj.jwtauth

import com.gaborpihaj.authmiddleware.JwtContentDecoder
import io.circe.{parser, Decoder}

package object circe {
  implicit def deriveJwtContentDecoder[T](implicit D: Decoder[T]): JwtContentDecoder[T] =
    new JwtContentDecoder[T] {
      override def decode(content: String): Either[String, T] = parser.decode[T](content).left.map(_.getMessage)
    }
}
