// Versions chosen for mutual compatibility (see android-app/README.md):
//   AGP 8.13.0 + Gradle 8.14.3, Kotlin Gradle plugin 2.3.21 (supports AGP 8.2.2-9.0.0, Gradle 7.6.3-9.3),
//   Chaquopy 17.1.0 (supports AGP 7.3-9.4, Python 3.10-3.15, minSdk >= 24).
plugins {
    id("com.android.application") version "8.13.0" apply false
    id("org.jetbrains.kotlin.android") version "2.3.21" apply false
    id("com.chaquo.python") version "17.1.0" apply false
}
