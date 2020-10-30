package com.gaborpihaj.authmiddleware

trait JwtContentDecoder[C] {
  def decode(content: String): Either[String, C]
}

object JwtContentDecoder {
  def apply[C](implicit ev: JwtContentDecoder[C]): JwtContentDecoder[C] = ev
}
