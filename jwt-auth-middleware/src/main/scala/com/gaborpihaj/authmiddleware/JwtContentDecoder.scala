package com.gaborpihaj.authmiddleware

trait JwtContentDecoder[C] {
  def decode(content: String): Either[String, C]
}
