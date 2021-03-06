package com.gaborpihaj.authmiddleware

sealed trait Error
case object InvalidToken extends Error
case object MissingAuthHeader extends Error
case object InvalidAuthHeader extends Error
case object MissingToken extends Error
case object ExpiredToken extends Error
case class JwtContentDecoderError(message: String) extends Error
