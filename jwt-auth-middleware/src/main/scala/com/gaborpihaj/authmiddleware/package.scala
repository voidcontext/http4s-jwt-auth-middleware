package com.gaborpihaj

import pdi.jwt.JwtClaim

import scala.util.Try

package object authmiddleware {
  private[authmiddleware] type JwtTokenDecoder = String => Try[JwtClaim]
}
