package com.gaborpihaj

import scala.util.Try

import pdi.jwt.JwtClaim

package object authmiddleware {
  private[authmiddleware] type JwtTokenDecoder = String => Try[JwtClaim]
}
