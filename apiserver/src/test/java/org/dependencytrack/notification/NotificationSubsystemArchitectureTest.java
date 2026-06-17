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
package org.dependencytrack.notification;

import alpine.persistence.AbstractAlpineQueryManager;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeJars;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeTests;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.dependencytrack.notification.proto.v1.Notification;

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
class NotificationSubsystemArchitectureTest {

    @ArchTest
    static final ArchRule mustOnlyBeCreatedThroughNotificationFactory =
            noClasses()
                    .that().resideOutsideOfPackages(
                            "org.dependencytrack.notification..",
                            "org.dependencytrack.proto..")
                    .should().callMethod(Notification.class, "newBuilder")
                    .because("""
                            All notifications must be created through NotificationFactory. \
                            This ensures that critical fields such as ID and timestamp are always set.""");

    @ArchTest
    static final ArchRule mustNotModifyCoreNotificationFieldsOutsideOfNotificationFactory =
            noClasses()
                    .that().areNotAssignableTo(org.dependencytrack.notification.api.NotificationFactory.class)
                    .and().areNotAssignableTo(org.dependencytrack.notification.api.TestNotificationFactory.class)
                    // Workaround for the fact that ArchUnit's callMethod() predicate
                    // does not yet inspect lambda code: https://github.com/TNG/ArchUnit/issues/981
                    .should().accessTargetWhere(target(owner(equivalentTo(Notification.Builder.class)))
                            .and(nameMatching("set(Id|Timestamp|Scope|Group|Level)")))
                    .because("""
                            The notification fields id, timestamp, scope, group, and level must \
                            only be set by NotificationFactory. This ensures consistency.""");

    @ArchTest
    static final ArchRule mustNotUseJdoApi =
            noClasses()
                    .that().resideInAPackage("org.dependencytrack.notification..")
                    .and().areNotAssignableTo(JdoNotificationEmitter.class)
                    .should().dependOnClassesThat().areAssignableTo(AbstractAlpineQueryManager.class)
                    .orShould().dependOnClassesThat().resideInAPackage("javax.jdo..")
                    .because("""
                            The notification subsystem should not use the JDO API to perform \
                            persistence operations. The system must be as lightweight as possible.""");

}
