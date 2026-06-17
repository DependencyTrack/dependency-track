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
package org.dependencytrack.persistence.jdbi;

import com.tngtech.archunit.core.domain.JavaAnnotation;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaParameterizedType;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeJars;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeTests;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.library.freeze.FreezingArchRule;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.util.HashSet;
import java.util.Set;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;

@AnalyzeClasses(
        packages = "org.dependencytrack.persistence.jdbi",
        importOptions = {DoNotIncludeTests.class, DoNotIncludeJars.class})
class DaoArchitectureTest {

    private static final Set<String> WRAPPER_TYPES = Set.of(
            "java.util.List",
            "java.util.Set",
            "java.util.Collection",
            "java.util.Optional",
            "java.util.Map",
            "org.dependencytrack.common.pagination.Page");

    @ArchTest
    static final ArchRule daoQueryMethodsMustNotReturnJdoModelClasses =
            FreezingArchRule.freeze(
                    methods()
                            .that().areDeclaredInClassesThat().haveSimpleNameEndingWith("Dao")
                            .and().areDeclaredInClassesThat().resideInAPackage("org.dependencytrack.persistence.jdbi")
                            .and().areNotAnnotatedWith(SqlUpdate.class)
                            .and().areNotAnnotatedWith(SqlBatch.class)
                            .should(new ArchCondition<>("not return model classes") {
                                @Override
                                public void check(JavaMethod method, ConditionEvents events) {
                                    for (JavaClass leafType : extractLeafTypes(method.getReturnType())) {
                                        if (isModelClass(leafType)) {
                                            events.add(SimpleConditionEvent.violated(
                                                    method,
                                                    "%s returns model class %s".formatted(
                                                            method.getFullName(), leafType.getName())));
                                        }
                                    }
                                }
                            }));

    @ArchTest
    static final ArchRule daosMustNotUseBeanMapperWithJdoClasses =
            FreezingArchRule.freeze(
                    classes()
                            .that().haveSimpleNameEndingWith("Dao")
                            .and().resideInAPackage("org.dependencytrack.persistence.jdbi")
                            .should(new ArchCondition<>("not use @RegisterBeanMapper with model classes") {
                                @Override
                                public void check(JavaClass daoClass, ConditionEvents events) {
                                    for (JavaAnnotation<?> annotation : daoClass.getAnnotations()) {
                                        checkBeanMapperAnnotation(daoClass, "<class>", annotation, events);
                                    }
                                    daoClass.getMethods().forEach(method -> {
                                        for (JavaAnnotation<?> annotation : method.getAnnotations()) {
                                            checkBeanMapperAnnotation(daoClass, method.getName(), annotation, events);
                                        }
                                    });
                                }
                            }));

    @ArchTest
    static final ArchRule rowMappersMustNotTargetJdoModelClasses =
            FreezingArchRule.freeze(
                    classes()
                            .that().resideInAPackage("org.dependencytrack.persistence.jdbi..")
                            .and().implement(org.jdbi.v3.core.mapper.RowMapper.class)
                            .should(new ArchCondition<>("not target model classes") {
                                @Override
                                public void check(JavaClass mapperClass, ConditionEvents events) {
                                    for (JavaType iface : mapperClass.getInterfaces()) {
                                        if (iface instanceof final JavaParameterizedType paramType
                                                && paramType.toErasure().isEquivalentTo(org.jdbi.v3.core.mapper.RowMapper.class)) {
                                            for (JavaType arg : paramType.getActualTypeArguments()) {
                                                if (arg instanceof final JavaClass targetClass && isModelClass(targetClass)) {
                                                    events.add(SimpleConditionEvent.violated(
                                                            mapperClass,
                                                            "%s maps to model class %s".formatted(
                                                                    mapperClass.getName(), targetClass.getName())));
                                                }
                                            }
                                        }
                                    }
                                }
                            }));

    private static boolean isModelClass(JavaClass javaClass) {
        // NB: Records in the model package (FindingKey etc.) are the migration target, not the problem.
        if (javaClass.isRecord()) {
            return false;
        }

        return javaClass.getPackageName().equals("org.dependencytrack.model")
                || javaClass.getPackageName().equals("alpine.model");
    }

    private static Set<JavaClass> extractLeafTypes(JavaType type) {
        var result = new HashSet<JavaClass>();
        collectLeafTypes(type, result);
        return result;
    }

    private static void collectLeafTypes(JavaType type, Set<JavaClass> result) {
        if (type instanceof final JavaParameterizedType paramType) {
            if (WRAPPER_TYPES.contains(paramType.toErasure().getName())) {
                for (JavaType arg : paramType.getActualTypeArguments()) {
                    collectLeafTypes(arg, result);
                }
            } else {
                result.add(paramType.toErasure());
            }
        } else if (type instanceof JavaClass javaClass) {
            result.add(javaClass);
        }
    }

    private static void checkBeanMapperAnnotation(
            JavaClass owner, String location, JavaAnnotation<?> annotation, ConditionEvents events) {
        String annotationType = annotation.getRawType().getName();
        if ("org.jdbi.v3.sqlobject.config.RegisterBeanMapper".equals(annotationType)) {
            annotation.get("value").ifPresent(value -> {
                if (value instanceof final JavaClass targetClass && isModelClass(targetClass)) {
                    events.add(SimpleConditionEvent.violated(owner,
                            "%s#%s uses @RegisterBeanMapper with model class %s".formatted(
                                    owner.getName(), location, targetClass.getName())));
                }
            });
        } else if ("org.jdbi.v3.sqlobject.config.RegisterBeanMappers".equals(annotationType)) {
            annotation.get("value").ifPresent(value -> {
                if (value instanceof final JavaAnnotation<?>[] nested) {
                    for (JavaAnnotation<?> inner : nested) {
                        checkBeanMapperAnnotation(owner, location, inner, events);
                    }
                }
            });
        }
    }

}
