import groovy.lang.GroovyObject
import groovy.lang.MetaClass
import org.gradle.api.internal.tasks.testing.junitplatform.JUnitPlatformTestFramework
import org.gradle.kotlin.dsl.resolver.buildSrcSourceRootsFilePath
import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.jfrog.gradle.plugin.artifactory.dsl.PublisherConfig
import org.jfrog.gradle.plugin.artifactory.dsl.ResolverConfig

object Version {
    const val astrea = "0.8.7-SNAPSHOT"
    const val kotlin = "1.3.0"
    const val artifactory = "4.8.1"
    const val junit = "5.3.1"
    const val jose4j = "0.6.4"
    const val mockito = "2.23.0"
    const val jBcrypt = "0.4"
    const val apacheHttpClient = "4.5.6"
    const val klaxon = "3.0.1"
    const val spek = "2.0.0-rc.1"
    const val assertj = "3.11.1"
}

val astrea = "astrea"
group = "io.imulab"
version = Version.astrea

repositories {
    jcenter()
    mavenCentral()
    maven {
        url = uri("https://dl.bintray.com/spekframework/spek")
    }
}

plugins {
    java
    jacoco
    `maven-publish`
    `build-scan`
    kotlin("jvm") version "1.3.0"
    id("org.jetbrains.dokka") version "0.9.16"
    id("com.jfrog.artifactory") version "4.8.1"
}

dependencies {
    implementation(kotlin(module = "stdlib-jdk8", version = Version.kotlin))
    implementation("org.bitbucket.b_c:jose4j:${Version.jose4j}")
    implementation("org.mindrot:jbcrypt:${Version.jBcrypt}")
    implementation("org.apache.httpcomponents:httpclient:${Version.apacheHttpClient}")

    testImplementation("org.junit.jupiter:junit-jupiter-api:${Version.junit}")
    testImplementation("org.junit.jupiter:junit-jupiter-params:${Version.junit}")
    testImplementation("org.mockito:mockito-core:${Version.mockito}")
    testImplementation("com.beust:klaxon:${Version.klaxon}")
    testImplementation("org.spekframework.spek2:spek-dsl-jvm:${Version.spek}") {
        exclude(group = "org.jetbrains.kotlin")
    }
    testImplementation("org.spekframework.spek2:spek-runner-junit5:${Version.spek}") {
        exclude(group = "org.junit.platform")
        exclude(group = "org.jetbrains.kotlin")
    }
    testImplementation("org.assertj:assertj-core:${Version.assertj}")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:${Version.junit}")
    testRuntimeOnly("org.jetbrains.kotlin:kotlin-reflect:${Version.kotlin}")
}

buildScan {
    setTermsOfServiceUrl("https://gradle.com/terms-of-service")
    setTermsOfServiceAgree("yes")
    publishAlways()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.withType<Test> {
    useJUnitPlatform {
        includeEngines("spek2")
    }
}

tasks.withType<JacocoReport> {
    reports {
        html.apply {
            isEnabled = true
        }
        xml.apply {
            isEnabled = true
        }
    }
}

jacoco {
    toolVersion = "0.8.2"
}

val dokka by tasks.getting(DokkaTask::class) {
    outputFormat = "html"
    outputDirectory = "$buildDir/javadoc"
}

val dokkaJar by tasks.creating(Jar::class) {
    group = JavaBasePlugin.DOCUMENTATION_GROUP
    description = "Assembles Kotlin docs with Dokka"
    classifier = "javadoc"
    from(dokka)
}

publishing {
    publications {
        create(astrea, MavenPublication::class.java) {
            from(components["java"])
            artifact(dokkaJar)
            pom {
                withXml {
                    asNode().appendNode("dependencies").let { depNode ->
                        configurations.implementation.allDependencies.forEach {
                            depNode.appendNode("dependency").apply {
                                appendNode("groupId", it.group)
                                appendNode("artifactId", it.name)
                                appendNode("version", it.version)
                                appendNode("scope", "compile")
                            }
                        }
                    }
                }
            }
        }
    }
}

artifactory {
    setContextUrl("http://artifactory.imulab.io/artifactory")
    publish(delegateClosureOf<PublisherConfig> {
        repository(delegateClosureOf<GroovyObject> {
            setProperty("repoKey", "gradle-dev-local")
            setProperty("username", requireEnv("ARTIFACTORY_USERNAME"))
            setProperty("password", requireEnv("ARTIFACTORY_PASSWORD"))
            setProperty("maven", true)
        })
        defaults(delegateClosureOf<GroovyObject> {
            invokeMethod("publications", astrea)
        })
    })
    resolve(delegateClosureOf<ResolverConfig> {
        repository(delegateClosureOf<GroovyObject> {
            setProperty("repoKey", "gradle-dev")
            setProperty("username", requireEnv("ARTIFACTORY_USERNAME"))
            setProperty("password", requireEnv("ARTIFACTORY_PASSWORD"))
            setProperty("maven", true)
        })
    })
}

fun requireEnv(name: String, hard: Boolean = false): String {
    return if (System.getenv(name) == null) {
        val message = "Environment variable $name not set."
        if (!hard) {
            System.out.println(message)
            ""
        } else
            throw IllegalStateException(message)
    } else {
        System.getenv(name)
    }
}