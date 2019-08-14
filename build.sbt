
val scalaLangVersion = "2.12.8"

val Http4sVersion = "0.20.4"
val JwtVersion = "3.1.0"

val ScalaTestVersion = "3.0.8"
val CirceVersion = "0.11.1"

val libraryName = "http4s-jwt-auth-middleware"
val libraryVersion = "0.0.1-SNAPSHOT"
val organisation = "com.gaborpihaj"

lazy val core = (project in file("jwt-auth-middleware"))
  .settings(
    organization := organisation,
    name := libraryName,
    version := libraryVersion,
    scalaVersion := scalaLangVersion,
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-server" % Http4sVersion,
      "org.http4s" %% "http4s-dsl" % Http4sVersion,

      "com.pauldijou" %% "jwt-core" % JwtVersion,

      "org.scalatest" %% "scalatest" % ScalaTestVersion % "test",

      "io.circe" %% "circe-generic" % CirceVersion % "test",
      "io.circe" %% "circe-parser" % CirceVersion % "test",

    ),

    addCompilerPlugin("org.typelevel" %% "kind-projector" % "0.10.3"),
    addCompilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.0"),
  )

scalacOptions ++= Seq(
  "-deprecation",
  "-encoding", "UTF-8",
  "-language:higherKinds",
  "-feature",
  "-Ypartial-unification",
  "-Xfatal-warnings",
)
