package com.gaborpihaj.authmiddleware

import java.security.PublicKey
import javax.crypto.SecretKey

import pdi.jwt.Jwt
import pdi.jwt.algorithms.{JwtAsymmetricAlgorithm, JwtHmacAlgorithm}

sealed trait JwtValidationContext
case class JwtHmacStringKey(key: String, algorithms: Seq[JwtHmacAlgorithm]) extends JwtValidationContext
case class JwtHmacSecretKey(secretKey: SecretKey, algorithms: Seq[JwtHmacAlgorithm]) extends JwtValidationContext
case class JwtPublicKey(publicKey: PublicKey, algorithms: Seq[JwtAsymmetricAlgorithm]) extends JwtValidationContext

object JwtValidationContext {
  private[authmiddleware] def decoder(encryptionContext: JwtValidationContext): JwtTokenDecoder =
    encryptionContext match {
      case JwtHmacStringKey(key, algorithms)   => (token) => Jwt.decode(token, key, algorithms)
      case JwtHmacSecretKey(key, algorithms)   => (token) => Jwt.decode(token, key, algorithms)
      case JwtPublicKey(publicKey, algorithms) => (token) => Jwt.decode(token, publicKey, algorithms)
    }
}
