/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.pkgmetadata.resolution;

import com.github.packageurl.PackageURL;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.cargo.CargoPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.composer.ComposerPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.cpan.CpanPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.gem.GemPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.gomodules.GoModulesPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.hackage.HackagePackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.hex.HexPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.maven.MavenPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.nixpkgs.NixpkgsPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.npm.NpmPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.nuget.NugetPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.pypi.PypiPackageMetadataResolverFactory;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Disabled // To be executed manually to not bother public registries too much.
class PackageMetadataResolverIT {

    static Stream<Arguments> shouldResolveFromPublicRegistry() {
        return Stream.of(
                Arguments.of(new CargoPackageMetadataResolverFactory(), "https://crates.io", "pkg:cargo/serde@1.0.200"),
                Arguments.of(new ComposerPackageMetadataResolverFactory(), "https://packagist.org", "pkg:composer/monolog/monolog@3.5.0"),
                Arguments.of(new CpanPackageMetadataResolverFactory(), "https://fastapi.metacpan.org", "pkg:cpan/Moose@2.2206"),
                Arguments.of(new GemPackageMetadataResolverFactory(), "https://rubygems.org", "pkg:gem/rails@7.1.3"),
                Arguments.of(new GoModulesPackageMetadataResolverFactory(), "https://proxy.golang.org", "pkg:golang/golang.org/x/text@v0.14.0"),
                Arguments.of(new HackagePackageMetadataResolverFactory(), "https://hackage.haskell.org", "pkg:hackage/aeson@2.2.1.0"),
                Arguments.of(new HexPackageMetadataResolverFactory(), "https://hex.pm", "pkg:hex/phoenix@1.7.10"),
                Arguments.of(new NixpkgsPackageMetadataResolverFactory(), "https://channels.nixos.org/nixpkgs-unstable/packages.json.br", "pkg:nixpkgs/curl@8.5.0"),
                Arguments.of(new MavenPackageMetadataResolverFactory(), "https://repo1.maven.org/maven2", "pkg:maven/org.apache.commons/commons-lang3@3.14.0"),
                Arguments.of(new MavenPackageMetadataResolverFactory(), "https://repo1.maven.org/maven2", "pkg:maven/org.apache.commons/commons-lang3@3.14.0?classifier=sources"),
                Arguments.of(new NpmPackageMetadataResolverFactory(), "https://registry.npmjs.org", "pkg:npm/lodash@4.17.21"),
                Arguments.of(new NugetPackageMetadataResolverFactory(), "https://api.nuget.org", "pkg:nuget/Newtonsoft.Json@13.0.3"),
                Arguments.of(new PypiPackageMetadataResolverFactory(), "https://pypi.org", "pkg:pypi/requests@2.31.0"),
                Arguments.of(new PypiPackageMetadataResolverFactory(), "https://pypi.org", "pkg:pypi/requests@2.31.0?file_name=requests-2.31.0.tar.gz"));
    }

    @ParameterizedTest(name = "{1}: {2}")
    @MethodSource
    void shouldResolveFromPublicRegistry(
            PackageMetadataResolverFactory factory,
            String repoUrl,
            String purlString) throws Exception {
        factory.init(createServiceRegistry());

        try (factory) {
            final PackageMetadataResolver resolver = factory.create();
            final var purl = new PackageURL(purlString);
            final var repo = new PackageRepository(factory.extensionName(), repoUrl, null, null);
            final PackageMetadata result = resolver.resolve(purl, repo, null);

            assertThat(result)
                    .as("%s: %s", factory.extensionName(), purl)
                    .isNotNull();
            assertThat(result.latestVersion())
                    .as("%s: latestVersion", factory.extensionName())
                    .isNotBlank();

            System.out.printf("[%s] %s -> latest=%s, artifactMeta=%s%n",
                    factory.extensionName(), purl, result.latestVersion(), result.artifactMetadata());
        }
    }

    private ServiceRegistry createServiceRegistry() {
        // NB: Nixpkgs needs redirects to be enabled b/c the Nix index
        // file uses them. Redirects are enabled in the HTTP client that
        // is used in production (org.dependencytrack.common.HttpClient).
        final HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        return new MutableServiceRegistry()
                .register(ConfigRegistry.class, new MockConfigRegistry(Map.of(), null, null, null))
                .register(CacheManager.class, new NoopCacheManager())
                .register(KeyValueStore.class, new MockKeyValueStore())
                .register(HttpClient.class, httpClient)
                .register(ProxySelector.class, ProxySelector.getDefault());
    }

}
