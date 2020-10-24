package com.gaborpihaj.jwtauth.circe

import io.circe.generic.auto._

import com.gaborpihaj.authmiddleware.JwtContentDecoder
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

case class UserClaim(id: String)

class DecoderSpec extends AnyFlatSpec with Matchers {
  "circe package" should "derive a JwtContentDecoder from a circe Decoder" in {
    val decoder = implicitly[JwtContentDecoder[UserClaim]]

    decoder.decode("""{"id": "some-id"}""") should be(Right(UserClaim("some-id")))
  }
}
