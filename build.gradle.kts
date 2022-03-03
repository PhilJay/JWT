plugins {
    java
    kotlin("jvm") version "1.6.0"
}

group = "com.philjay.jwt"
version = "1.2.2"
description = "JWT"
java.sourceCompatibility = JavaVersion.VERSION_14

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