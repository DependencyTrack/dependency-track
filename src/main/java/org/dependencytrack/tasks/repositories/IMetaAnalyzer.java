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
package org.dependencytrack.tasks.repositories;

import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import com.github.packageurl.PackageURL;

/**
 * Interface that defines Repository Meta Analyzers.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public interface IMetaAnalyzer {

    /**
     * Sets the base URL for the repository being used. If not specified, IMetaAnalyzer implementations
     * should fall back to a default value (if one is available).
     * @param baseUrl the base URL to the repository
     * @since 3.1.0
     */
    void setRepositoryBaseUrl(String baseUrl);

    /**
     * Sets the username and password (or access token) to use for authentication with the repository. Should not be used for repositories that do not
     * use Basic or Bearer authentication.
     * @param username the username for access to the repository.
     * @param password the password or access token to be used for the repository.
     * @param bearerToken the password or access token to be used for the repository.
     * @since 4.6.0
     */
    void setCredentials(String username, String password, String bearerToken);

    /**
     * Returns the type of repositry the analyzer supports.
     * @since 3.1.0
     */
    RepositoryType supportedRepositoryType();

    /**
     * Returns whether or not the analyzer is capable of supporting the ecosystem of the component.
     * @param component the component to analyze
     * @return true if analyzer can be used for this component, false if not
     * @since 3.1.0
     */
    boolean isApplicable(Component component);

    /**
     * The component to analyze.
     * @param component the component to analyze
     * @return a MetaModel object
     * @throws MetaAnalyzerException in case of any issue during metadata generation
     * @since 3.1.0
     */
    MetaModel analyze(Component component);

    /**
     * Convenience factory method that creates an IMetaAnalyzer implementation suitable
     * to analyze the specified component.
     * @param component the component to analyze
     * @return an IMetaAnalyzer implementation
     * @since 3.1.0
     */
    static IMetaAnalyzer build(Component component) {
        if (component.getPurl() != null) {
            if (PackageURL.StandardTypes.MAVEN.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new MavenMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.NPM.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new NpmMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.CARGO.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new CargoMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if ("cpan".equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new CpanMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.GEM.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new GemMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.NUGET.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new NugetMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.PYPI.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new PypiMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.COMPOSER.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new ComposerMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.HEX.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new HexMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.GOLANG.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new GoModulesMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if (PackageURL.StandardTypes.GITHUB.equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new GithubMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if ("hackage".equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new HackageMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            } else if ("nixpkgs".equals(component.getPurl().getType())) {
                IMetaAnalyzer analyzer = new NixpkgsMetaAnalyzer();
                if (analyzer.isApplicable(component)) {
                    return analyzer;
                }
            }
        }

        return new IMetaAnalyzer() {
            @Override
            public void setRepositoryBaseUrl(String baseUrl) {
            }

            @Override
            public void setCredentials(String username, String password, String bearerToken) {

            }

            @Override
            public boolean isApplicable(Component component) {
                return false;
            }

            public RepositoryType supportedRepositoryType() {
                return RepositoryType.UNSUPPORTED;
            }

            @Override
            public MetaModel analyze(Component component) {
                return new MetaModel(component);
            }
        };
    }

}
