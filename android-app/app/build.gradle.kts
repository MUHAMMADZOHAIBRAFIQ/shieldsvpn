import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.chaquo.python")
}

// The repository root holds the pqvpn Python package that the desktop clients and the server use.
val repoRoot: File = rootProject.projectDir.parentFile
val pqvpnPythonDir = layout.buildDirectory.dir("generated/pqvpn-python")

// The screen is a React app (android-app/ui, built with Node.js + Vite) shown in a WebView.
val uiDir: File = rootProject.file("ui")
val uiAssetsDir = layout.buildDirectory.dir("generated/ui-assets")
val npm = if (System.getProperty("os.name").lowercase().contains("windows")) "npm.cmd" else "npm"

// Release signing is optional and never stored in the repository. Pass the path of a keystore.properties
// (storeFile, storePassword, keyAlias, keyPassword; storeFile relative to that file) with
// -Pshieldsvpn.signing=<path>, or put one at android-app/keystore.properties (git-ignored).
val signingPropsFile: File = (findProperty("shieldsvpn.signing") as String?)
    ?.let { rootProject.file(it) } ?: rootProject.file("keystore.properties")
val signingProps = Properties().apply {
    if (signingPropsFile.isFile) signingPropsFile.inputStream().use { load(it) }
}

android {
    namespace = "com.shieldsvpn.vpn"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.shieldsvpn.vpn"
        minSdk = 24            // Chaquopy 17 minimum
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
        ndk {
            // OpenSSL (android-app/app/src/main/jniLibs) and Chaquopy's Python are built for these ABIs only.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (!signingProps.isEmpty) {
            create("release") {
                storeFile = signingPropsFile.parentFile.resolve(signingProps.getProperty("storeFile"))
                storePassword = signingProps.getProperty("storePassword")
                keyAlias = signingProps.getProperty("keyAlias")
                keyPassword = signingProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Without a keystore.properties the release APK is built unsigned (app-release-unsigned.apk).
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs {
            // pqvpn loads libcrypto_pqvpn.so through ctypes by absolute path, so it must exist as a real file
            // in nativeLibraryDir rather than only inside the APK.
            useLegacyPackaging = true
        }
    }

    buildFeatures {
        buildConfig = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = false
    }

    sourceSets {
        getByName("main") {
            assets.srcDir(uiAssetsDir)   // build/generated/ui-assets/ui/** -> assets/ui/** in the APK
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

// Only the modules the Android client needs; the portal, desktop UIs, TUN drivers and NetConfig stay out.
val syncPqvpnPython = tasks.register<Sync>("syncPqvpnPython") {
    from(repoRoot.resolve("pqvpn")) {
        include(
            "__init__.py", "android_client.py", "config.py", "handshake.py", "node.py", "pki.py",
            "protocol.py", "session.py", "wire.py",
            "crypto/__init__.py", "crypto/kdf.py", "crypto/ossl.py", "crypto/suites.py",
        )
        into("pqvpn")
    }
    into(pqvpnPythonDir)
}

chaquopy {
    defaultConfig {
        version = "3.13"
        // Keep .py sources (no build-machine Python needed, readable tracebacks in logcat).
        pyc {
            src = false
        }
    }
    sourceSets {
        getByName("main") {
            srcDir(pqvpnPythonDir.get().asFile)
        }
    }
}

// ---------------------------------------------------------------- React UI (Node.js)

val npmCiUi = tasks.register<Exec>("npmCiUi") {
    description = "Installs the React UI's pinned npm dependencies (package-lock.json)."
    workingDir = uiDir
    commandLine(npm, "ci", "--no-audit", "--no-fund")
    inputs.files(uiDir.resolve("package.json"), uiDir.resolve("package-lock.json"))
    outputs.file(uiDir.resolve("node_modules/.package-lock.json"))
}

val buildReactUi = tasks.register<Exec>("buildReactUi") {
    description = "Type-checks and bundles the React UI into build/generated/ui-assets/ui."
    dependsOn(npmCiUi)
    workingDir = uiDir
    commandLine(npm, "run", "build")
    inputs.dir(uiDir.resolve("src"))
    inputs.files(
        uiDir.resolve("index.html"), uiDir.resolve("vite.config.ts"), uiDir.resolve("tsconfig.json"),
        uiDir.resolve("package-lock.json"),
    )
    outputs.dir(uiAssetsDir)
}

val testReactUi = tasks.register<Exec>("testReactUi") {
    description = "Runs the React UI's unit tests (Vitest)."
    dependsOn(npmCiUi)
    workingDir = uiDir
    commandLine(npm, "test")
}

tasks.named("preBuild") { dependsOn(buildReactUi) }
tasks.matching { it.name == "testDebugUnitTest" }.configureEach { dependsOn(testReactUi) }

// Chaquopy reads the Python source directory in its merge/generate tasks: make sure it is populated first.
tasks.configureEach {
    if (name.contains("Python", ignoreCase = true) && name != "syncPqvpnPython") {
        dependsOn(syncPqvpnPython)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.11.0")
    implementation("androidx.core:core-splashscreen:1.2.0")   // branded splash held until the React UI is ready
    implementation("androidx.webkit:webkit:1.14.0")   // WebViewAssetLoader + origin-restricted WebMessageListener

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")   // real org.json for JVM unit tests (Android's is a stub)
}
