import xerial.sbt.Sonatype._

lazy val scala213 = "2.13.8"
lazy val supportedScalaVersions = List(scala213)

val Http4sVersion = "0.23.13"
val JwtVersion = "5.0.0"

val ScalaTestVersion = "3.2.12"
val CirceVersion = "0.14.2"

val libraryName = "http4s-jwt-auth-middleware"
val libraryVersion = "0.5.0"
val organisation = "com.gaborpihaj"

val website = "https://voidcontext.github.io/http4s-jwt-auth-middleware"

ThisBuild / organization := organisation
ThisBuild / scalaVersion := scala213

ThisBuild / version := libraryVersion
ThisBuild / homepage := Some(url(website))
ThisBuild / publishTo := sonatypePublishToBundle.value
// Following 2 lines need to get around https://github.com/sbt/sbt/issues/4275
ThisBuild / publishConfiguration := publishConfiguration.value.withOverwrite(true)
ThisBuild / publishLocalConfiguration := publishLocalConfiguration.value.withOverwrite(true)

ThisBuild / scalafixDependencies += "com.github.liancheng" %% "organize-imports" % "0.4.3"

lazy val publishSettings = List(
  licenses += ("MIT", url("http://opensource.org/licenses/MIT")),
  publishMavenStyle := true,
  sonatypeProjectHosting := Some(GitHubHosting("voidcontext", libraryName, "gabor.pihaj@gmail.com"))
)

lazy val defaultSettings = Seq(
  addCompilerPlugin(scalafixSemanticdb),
  crossScalaVersions := supportedScalaVersions,
  testOptions in Test += Tests.Argument(TestFrameworks.ScalaTest, "-oDF"),
  // // Following 2 lines need to get around https://github.com/sbt/sbt/issues/4275
  publishConfiguration := publishConfiguration.value.withOverwrite(true),
  publishLocalConfiguration := publishLocalConfiguration.value.withOverwrite(true)
)

lazy val root = (project in file("."))
  .settings(
    defaultSettings,
    skip in publish := true,
    micrositeName := libraryName,
    micrositeDescription := "A JWT based AuthenticationMiddleware for Http4s",
    micrositeDocumentationUrl := "docs/step-by-step-example.html",
    micrositeGithubOwner := "voidcontext",
    micrositeGithubRepo := libraryName,
    micrositeGitterChannel := false
//    micrositeCompilingDocsTool := WithMdoc
  )
  .dependsOn(jwtAuthMiddleware, jwtAuthCirce)
  .aggregate(jwtAuthMiddleware, jwtAuthCirce)
  .enablePlugins(MicrositesPlugin)

lazy val jwtAuthMiddleware = (project in file("jwt-auth-middleware"))
  .settings(
    name := libraryName,
    publishSettings,
    defaultSettings,
    libraryDependencies ++= Seq(
      "org.http4s"    %% "http4s-server" % Http4sVersion,
      "org.http4s"    %% "http4s-dsl"    % Http4sVersion,
      "com.pauldijou" %% "jwt-core"      % JwtVersion,
      "org.scalatest" %% "scalatest"     % ScalaTestVersion % "test",
      "io.circe"      %% "circe-generic" % CirceVersion     % "test",
      "io.circe"      %% "circe-parser"  % CirceVersion     % "test"
    ),
    addCompilerPlugin("org.typelevel" %% "kind-projector"     % "0.10.3"),
    addCompilerPlugin("com.olegpy"    %% "better-monadic-for" % "0.3.1")
  )

lazy val jwtAuthCirce = (project in file("jwt-auth-circe"))
  .settings(
    name := "http4s-jwt-auth-circe",
    publishSettings,
    defaultSettings,
    libraryDependencies ++= Seq(
      "io.circe"      %% "circe-generic" % CirceVersion,
      "io.circe"      %% "circe-parser"  % CirceVersion,
      "io.circe"      %% "circe-generic" % CirceVersion     % "test",
      "org.scalatest" %% "scalatest"     % ScalaTestVersion % "test"
    )
  )
  .dependsOn(jwtAuthMiddleware)

addCommandAlias("fmt", ";scalafix ;test:scalafix ;scalafmtAll ;scalafmtSbt")
addCommandAlias("prePush", ";fmt ;clean ;reload ;test")
