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
package org.dependencytrack.common;

import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeJars;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeTests;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.core.domain.JavaAccess.Predicates.target;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.equivalentTo;
import static com.tngtech.archunit.core.domain.properties.HasName.Predicates.nameMatching;
import static com.tngtech.archunit.core.domain.properties.HasOwner.Predicates.With.owner;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(
        packages = "org.dependencytrack",
        importOptions = {
            DoNotIncludeJars.class,
            DoNotIncludeTests.class,
        })
class HttpClientArchitectureTest {

    @ArchTest
    @SuppressWarnings("unused")
    static final ArchRule mustOnlyCreateHttpClientsThroughWrapper = noClasses()
            .that()
            .areNotAssignableTo(HttpClient.class)
            .and()
            .resideOutsideOfPackage("org.dependencytrack.plugin.testing..")
            // Workaround for the fact that ArchUnit's callMethod() predicate
            // does not yet inspect lambda code: https://github.com/TNG/ArchUnit/issues/981
            .should()
            .accessTargetWhere(target(owner(equivalentTo(java.net.http.HttpClient.class)))
                    .and(nameMatching("newBuilder|newHttpClient")))
            .because("""
                HTTP clients must be created through org.dependencytrack.common.HttpClient, \
                or obtained from ExtensionContext in plugins. Other clients bypass \
                dt.outbound.allowed-destinations and the proxy configuration.\
                """);
}
