package com.gaborpihaj.jwtauth.circe

import io.circe.generic.auto._
import org.scalatest.FlatSpec
import org.scalatest.Matchers
import com.gaborpihaj.authmiddleware.JwtContentDecoder

case class UserClaim(id: String)

class DecoderSpec extends FlatSpec with Matchers {
  "circe package" should "derive a JwtContentDecoder from a circe Decoder" in {
    val decoder = implicitly[JwtContentDecoder[UserClaim]]

    decoder.decode("""{"id": "some-id"}""") should be(Right(UserClaim("some-id")))
  }
}

