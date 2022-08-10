package org.dependencytrack.parser.osv.model;

public enum Ecosystem {

    ANDROID("Android"),
    GSD("GSD"),
    GO("Go"),
    ERLANG("Hex"),
    JAVASCRIPT("JavaScript"),
    LINUX("Linux"),
    MAVEN("Maven"),
    NUGET("NuGet"),
    OSSFUZZ("OSS-Fuzz"),
    PACKAGIST("Packagist"),
    PYPI("PyPI"),
    RUBYGEMS("RubyGems"),
    UVI("UVI"),
    RUST("crates.io"),
    NPM("npm"),
    DWF("DWF"),
    DEBIAN("Debian"),
    GITHUB_ACTIONS("GitHub Actions");

    private final String value;

    Ecosystem(final String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
