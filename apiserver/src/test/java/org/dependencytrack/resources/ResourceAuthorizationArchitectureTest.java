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
package org.dependencytrack.resources;

import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.auth.PermissionRequired;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeJars;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeTests;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.Path;

import java.util.Set;

import static com.tngtech.archunit.base.DescribedPredicate.describe;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;

@AnalyzeClasses(
        packages = "org.dependencytrack.resources",
        importOptions = {
                DoNotIncludeJars.class,
                DoNotIncludeTests.class,
        })
class ResourceAuthorizationArchitectureTest {

    // Methods that intentionally require authentication but not a specific permission.
    private static final Set<String> PERMISSION_ANNOTATION_ALLOWLIST = Set.of(
            "CalculatorResource.getCvssScores",
            "CalculatorResource.getOwaspRRScores",
            "CweResource.getCwe",
            "CweResource.getCwes",
            "EventResource.isTokenBeingProcessed",
            "LicenseResource.getLicense",
            "LicenseResource.getLicenseListing",
            "LicenseResource.getLicenses",
            "RepositoryResource.getRepositoryMetaComponent",
            "TeamResource.availableTeams",
            "TeamResource.getSelf",
            "UserResource.getSelf",
            "UserResource.getSelfPermissions",
            "UserResource.logout",
            "UserResource.updateSelf");

    @ArchTest
    static final ArchRule resourceMethodsMustDeclarePermissions =
            methods()
                    .that().areMetaAnnotatedWith(HttpMethod.class)
                    .should(new ArchCondition<>("be annotated with @PermissionRequired or @AuthenticationNotRequired") {
                        @Override
                        public void check(final JavaMethod method, final ConditionEvents events) {
                            final String key = method.getOwner().getSimpleName() + "." + method.getName();
                            if (PERMISSION_ANNOTATION_ALLOWLIST.contains(key)) {
                                return;
                            }

                            final boolean hasPermissionRequired = method.isAnnotatedWith(PermissionRequired.class);
                            final boolean hasAuthNotRequired = method.isAnnotatedWith(AuthenticationNotRequired.class);
                            if (!hasPermissionRequired && !hasAuthNotRequired) {
                                events.add(SimpleConditionEvent.violated(method, """
                                        %s is missing @PermissionRequired or @AuthenticationNotRequired\
                                        """.formatted(method.getFullName())));
                            }
                        }
                    });

    @ArchTest
    static final ArchRule resourceClassesMustExtendAbstractApiResource =
            classes()
                    .that(describe("are annotated with @Path or implement a @Path-annotated interface",
                            (JavaClass javaClass) -> javaClass.isAnnotatedWith(Path.class)
                                    || javaClass.getRawInterfaces().stream()
                                    .anyMatch(iface -> iface.isAnnotatedWith(Path.class))))
                    // v1 OpenApiResource extends BaseOpenApiResource from Swagger library.
                    .and().doNotHaveSimpleName("OpenApiResource")
                    .should().beAssignableTo(AbstractApiResource.class)
                    .because("""
                            Resource classes must extend AbstractApiResource to have access \
                            to helper methods for project access control enforcement.""");

}
