plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The Rust core (crates/mobile) is built with cargo-ndk and its Kotlin bindings are generated
// by UniFFI from the built library, so they can never drift apart.
val repoRoot: File = rootDir.parentFile
val rustLibs = layout.buildDirectory.dir("rustJniLibs")
val uniffiKotlin = layout.buildDirectory.dir("generated/uniffi")
val abis = listOf("arm64-v8a", "x86_64")

val cargoBuild by tasks.registering(Exec::class) {
    group = "rust"
    workingDir = repoRoot
    val out = rustLibs.get().asFile
    commandLine(
        listOf("cargo", "ndk") + abis.flatMap { listOf("-t", it) } +
            listOf("--platform", "26", "-o", out.absolutePath, "build", "--release", "--locked", "-p", "velora-mobile"),
    )
    inputs.files(fileTree(repoRoot.resolve("crates")) { include("**/*.rs", "**/Cargo.toml") })
    inputs.file(repoRoot.resolve("Cargo.lock"))
    outputs.dir(out)
}

val uniffiBindings by tasks.registering(Exec::class) {
    group = "rust"
    dependsOn(cargoBuild)
    workingDir = repoRoot
    val out = uniffiKotlin.get().asFile
    commandLine(
        "cargo", "run", "--locked", "-p", "uniffi-bindgen", "--", "generate",
        "--library", rustLibs.get().asFile.resolve("arm64-v8a/libvelora_mobile.so").absolutePath,
        "--language", "kotlin", "--no-format", "--out-dir", out.absolutePath,
    )
    inputs.files(cargoBuild)
    outputs.dir(out)
}

android {
    namespace = "io.github.yanngc32.velora"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.yanngc32.velora"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "0.2.0"
        ndk { abiFilters += abis }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }

    sourceSets["main"].java.srcDir(uniffiKotlin)
    sourceSets["main"].jniLibs.srcDir(rustLibs)
}

tasks.named("preBuild") { dependsOn(uniffiBindings) }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    // UniFFI's Kotlin bindings call into Rust through JNA.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
    testImplementation("junit:junit:4.13.2")
}
