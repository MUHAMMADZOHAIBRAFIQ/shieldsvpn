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

// Where the app finds the portal for Free-with-ads, sign-in and Pro (pqvpn/portal/api.py).  Deployment-specific,
// so never in the repository: android-app/deploy.properties (git-ignored) or -Pshieldsvpn.deploy=<path>.  Keys:
//   portalUrl         https://host:port/ of the portal
//   portalPin         SHA-256 of the portal's TLS certificate (64 hex digits) when it is self-signed (playit.gg)
//   portalAllowHttp   true only to test against a plain-http portal (emulator: http://10.0.2.2:8800/)
//   admobAppId, admobRewardedId, admobInterstitialId   your AdMob IDs (default: Google's public test IDs)
//   store             "play" for the Google Play build: Pro through Google Play Billing, no profile-file import, and
//                     portalUrl + privacyPolicyUrl required.  "direct" (default): APKs you hand out yourself.
//   privacyPolicyUrl  https:// address of the privacy policy, linked from the app (Google Play requires it in-app)
// Without a portalUrl the app works as before: profiles are imported from the portal's ZIP file.
val deployPropsFile: File = (findProperty("shieldsvpn.deploy") as String?)
    ?.let { rootProject.file(it) } ?: rootProject.file("deploy.properties")
val deployProps = Properties().apply {
    if (deployPropsFile.isFile) deployPropsFile.inputStream().use { load(it) }
}

/** A deploy.properties value, checked so it cannot break out of the generated BuildConfig string. */
fun deploy(key: String, default: String, pattern: Regex): String {
    val v = deployProps.getProperty(key, default).trim()
    if (!pattern.matches(v)) throw GradleException("deploy.properties: $key has an invalid value")
    return v
}
val portalUrl = deploy("portalUrl", "", Regex("""(https?://[A-Za-z0-9.\-\[\]:]+(:\d+)?/?)?"""))
val portalPin = deploy("portalPin", "", Regex("""([0-9a-fA-F]{64})?"""))
val portalAllowHttp = deploy("portalAllowHttp", "false", Regex("true|false"))
val admobId = Regex("""ca-app-pub-\d+[~/]\d+""")
val admobAppId = deploy("admobAppId", "ca-app-pub-3940256099942544~3347511713", admobId)
val admobRewardedId = deploy("admobRewardedId", "ca-app-pub-3940256099942544/5224354917", admobId)
val admobInterstitialId = deploy("admobInterstitialId", "ca-app-pub-3940256099942544/1033173712", admobId)
val store = deploy("store", "direct", Regex("play|direct"))
val privacyPolicyUrl = deploy("privacyPolicyUrl", "", Regex("""(https://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~/\-]*)?)?"""))
if (store == "play" && (portalUrl.isEmpty() || privacyPolicyUrl.isEmpty())) {
    throw GradleException("deploy.properties: store=play needs portalUrl and privacyPolicyUrl (Google Play requirements)")
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
        buildConfigField("String", "PORTAL_URL", "\"$portalUrl\"")
        buildConfigField("String", "PORTAL_PIN", "\"${portalPin.lowercase()}\"")
        buildConfigField("boolean", "PORTAL_ALLOW_HTTP", portalAllowHttp)
        buildConfigField("String", "ADMOB_REWARDED_ID", "\"$admobRewardedId\"")
        buildConfigField("String", "ADMOB_INTERSTITIAL_ID", "\"$admobInterstitialId\"")
        buildConfigField("boolean", "PLAY_STORE", (store == "play").toString())
        buildConfigField("String", "PRIVACY_URL", "\"$privacyPolicyUrl\"")
        manifestPlaceholders["admobAppId"] = admobAppId
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
            // Passwords and device tokens travel to the portal: a release build never talks plain HTTP, whatever
            // deploy.properties says (portalAllowHttp is for emulator tests with debug builds only).
            buildConfigField("boolean", "PORTAL_ALLOW_HTTP", "false")
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
            "__init__.py", "account_client.py", "android_client.py", "config.py", "handshake.py", "node.py", "pki.py",
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
    // Free plan: rewarded video ads (free VPN time) and an interstitial on connect, with Google's consent form
    // (UMP) for users where the law requires asking first.  Used only when the portal turns ads on.
    implementation("com.google.android.gms:play-services-ads:24.4.0")
    implementation("com.google.android.ump:user-messaging-platform:3.2.0")
    // Pro in the Play Store build: Google Play Billing (Play's payments policy).  The portal checks every purchase.
    implementation("com.android.billingclient:billing:9.1.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")   // real org.json for JVM unit tests (Android's is a stub)
}
