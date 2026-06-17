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

import org.dependencytrack.pkgmetadata.resolution.cargo.CargoPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.composer.ComposerPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.cpan.CpanPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.gem.GemPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.github.GithubPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.gomodules.GoModulesPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.hackage.HackagePackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.hex.HexPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.maven.MavenPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.nixpkgs.NixpkgsPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.npm.NpmPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.nuget.NugetPackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.pypi.PypiPackageMetadataResolverFactory;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;

import java.util.Collection;
import java.util.List;

public final class DefaultPackageMetadataResolutionPlugin implements Plugin {

    @Override
    public Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(
                new CargoPackageMetadataResolverFactory(),
                new ComposerPackageMetadataResolverFactory(),
                new CpanPackageMetadataResolverFactory(),
                new GemPackageMetadataResolverFactory(),
                new GithubPackageMetadataResolverFactory(),
                new GoModulesPackageMetadataResolverFactory(),
                new HackagePackageMetadataResolverFactory(),
                new HexPackageMetadataResolverFactory(),
                new MavenPackageMetadataResolverFactory(),
                new NixpkgsPackageMetadataResolverFactory(),
                new NpmPackageMetadataResolverFactory(),
                new NugetPackageMetadataResolverFactory(),
                new PypiPackageMetadataResolverFactory());
    }

}
