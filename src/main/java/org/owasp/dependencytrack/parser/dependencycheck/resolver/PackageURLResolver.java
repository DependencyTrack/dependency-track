/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.parser.dependencycheck.resolver;

import alpine.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.owasp.dependencytrack.parser.dependencycheck.model.Dependency;
import org.owasp.dependencytrack.parser.dependencycheck.model.Identifier;
import java.util.TreeMap;

/**
 * Attempts to resolve the PackageURL from high-quality and reliable evidence.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class PackageURLResolver implements IResolver {

    private static final Logger LOGGER = Logger.getLogger(PackageURLResolver.class);

    /**
     * {@inheritDoc}
     */
    public PackageURL resolve(Dependency dependency) {
        try {
            if (dependency.getIdentifiers() != null && dependency.getIdentifiers().getIdentifiers() != null) {
                for (Identifier identifier : dependency.getIdentifiers().getIdentifiers()) {
                    if ("maven".equals(identifier.getType())
                            && ("HIGHEST".equals(identifier.getConfidence()) || "HIGH".equals(identifier.getConfidence()))
                            || identifier == dependency.getIdentifier()) { // account for identifier in related dependency without confidence

                        final GAV gav = parseIdentifier(identifier);
                        if (dependency.getFileName() != null && dependency.getFileName().contains(".")) {
                            final String extension = dependency.getFileName().substring(
                                    dependency.getFileName().lastIndexOf(".") + 1, dependency.getFileName().length()
                            );
                            TreeMap<String, String> qualifiers = new TreeMap<>();
                            qualifiers.put("type", extension);
                            return new PackageURL(PackageURL.StandardTypes.MAVEN, gav.group, gav.artifact, gav.version, qualifiers, null);
                        } else {
                            return new PackageURL(PackageURL.StandardTypes.MAVEN, gav.group, gav.artifact, gav.version, null, null);
                        }

                    } else if ("npm".equals(identifier.getType())
                            && ("HIGHEST".equals(identifier.getConfidence()) || "HIGH".equals(identifier.getConfidence()))
                            || identifier == dependency.getIdentifier()) { // account for identifier in related dependency without confidence
                        final GAV gav = parseIdentifier(identifier);
                        return new PackageURL(PackageURL.StandardTypes.NPM, gav.group, gav.artifact, gav.version, null, null);
                    }

                    // todo: add PHP Composer, NuGet, Rubygems, and other supported types. Pull requests welcome :-)
                }

            }
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("An error occurred while attempting to resolve PackageURL", e);
        }
        return null;
    }

    private GAV parseIdentifier(Identifier identifier) {
        if (identifier == null || identifier.getName() == null) {
        	throw new IllegalArgumentException("Must specify an identifier with a name");
        }
        
        String name = identifier.getName();
        if (name.startsWith("(") && name.endsWith(")")) {
        	name = name.substring(1, name.length()-1);
        }
        
        final GAV gav = new GAV();
        final String[] parts = name.split(":");
        if (parts.length == 2) {
            gav.artifact = parts[0];
            gav.version = parts[1];
        } else if (parts.length == 3) {
            gav.group = parts[0];
            gav.artifact = parts[1];
            gav.version = parts[2];
        } else {
        	throw new IllegalArgumentException("Got bad identifier " + name);
        }
        return gav;
    }

    private class GAV {
        private String group = null;
        private String artifact = null;
        private String version = null;
    }
}
