plugins {
    java
    `maven-publish`
    kotlin("jvm") version "1.6.0"
}

val g = "com.philjay.jwt"
val v = "1.2.4"
val desc = "JWT"

group = g
version = v
description = desc
java.sourceCompatibility = JavaVersion.VERSION_14

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = g
            artifactId = desc
            version = v

            from(components["java"])
        }
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.code.gson:gson:2.9.0")
    testImplementation("commons-codec:commons-codec:1.14")
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
        jvmTarget = "14"
    }
}