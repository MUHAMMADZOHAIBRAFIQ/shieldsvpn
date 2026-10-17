pluginManagement {
    repositories {
        google()
        mavenCentral()          // Chaquopy's Gradle plugin is published on Maven Central
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "ShieldsVPN"
include(":app")
