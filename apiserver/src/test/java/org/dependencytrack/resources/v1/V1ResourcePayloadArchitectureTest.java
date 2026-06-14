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
package org.dependencytrack.resources.v1;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaAnnotation;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaParameter;
import com.tngtech.archunit.core.domain.JavaParameterizedType;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeJars;
import com.tngtech.archunit.core.importer.ImportOption.DoNotIncludeTests;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.library.freeze.FreezingArchRule;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.MatrixParam;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;

import javax.jdo.annotations.PersistenceCapable;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import static com.tngtech.archunit.lang.SimpleConditionEvent.violated;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;

@AnalyzeClasses(
        packages = "org.dependencytrack.resources.v1",
        importOptions = {DoNotIncludeTests.class, DoNotIncludeJars.class})
class V1ResourcePayloadArchitectureTest {

    private static final Set<String> HTTP_METHOD_ANNOTATIONS = Set.of(
            GET.class.getName(),
            POST.class.getName(),
            PUT.class.getName(),
            DELETE.class.getName(),
            PATCH.class.getName(),
            HEAD.class.getName(),
            OPTIONS.class.getName());

    private static final Set<String> NON_BODY_PARAMETER_ANNOTATIONS = Set.of(
            PathParam.class.getName(),
            QueryParam.class.getName(),
            HeaderParam.class.getName(),
            FormParam.class.getName(),
            CookieParam.class.getName(),
            MatrixParam.class.getName(),
            BeanParam.class.getName(),
            Context.class.getName());

    private static final Set<String> WRAPPER_TYPES = Set.of(
            List.class.getName(),
            Set.class.getName(),
            Collection.class.getName(),
            Optional.class.getName(),
            Map.class.getName());

    @ArchTest
    @SuppressWarnings("unused")
    static final ArchRule v1ResourceHandlerMethodsMustNotAcceptJdoModelsAsRequestBody =
            FreezingArchRule.freeze(
                    methods()
                            .that(new DescribedPredicate<>("are JAX-RS resource handler methods") {
                                @Override
                                public boolean test(JavaMethod method) {
                                    return isHttpHandlerMethod(method);
                                }
                            })
                            .should(new ArchCondition<>("not accept JDO model classes as request body") {
                                @Override
                                public void check(JavaMethod method, ConditionEvents events) {
                                    for (JavaParameter parameter : method.getParameters()) {
                                        if (!isRequestBodyParameter(parameter)) {
                                            continue;
                                        }

                                        for (JavaClass leafType : extractLeafTypes(parameter.getType())) {
                                            if (isJdoModelClass(leafType)) {
                                                events.add(violated(
                                                        method,
                                                        "%s accepts JDO model class %s as request body".formatted(
                                                                method.getFullName(), leafType.getName())));
                                            }
                                        }
                                    }
                                }
                            }));

    @ArchTest
    @SuppressWarnings("unused")
    static final ArchRule v1ResourceSwaggerResponseSchemasMustNotReferenceJdoModels =
            FreezingArchRule.freeze(
                    methods()
                            .that(new DescribedPredicate<>("are JAX-RS resource handler methods") {
                                @Override
                                public boolean test(JavaMethod method) {
                                    return isHttpHandlerMethod(method);
                                }
                            })
                            .should(new ArchCondition<>("not declare JDO model classes in Swagger response schemas") {
                                @Override
                                public void check(JavaMethod method, ConditionEvents events) {
                                    for (JavaAnnotation<?> annotation : method.getAnnotations()) {
                                        collectSwaggerSchemaImplementations(annotation, method, events);
                                    }
                                }
                            }));

    private static boolean isHttpHandlerMethod(JavaMethod method) {
        for (JavaAnnotation<?> annotation : method.getAnnotations()) {
            if (HTTP_METHOD_ANNOTATIONS.contains(annotation.getRawType().getName())) {
                return true;
            }
        }

        return false;
    }

    private static boolean isRequestBodyParameter(JavaParameter parameter) {
        for (JavaAnnotation<?> annotation : parameter.getAnnotations()) {
            if (NON_BODY_PARAMETER_ANNOTATIONS.contains(annotation.getRawType().getName())) {
                return false;
            }
        }

        return true;
    }

    private static boolean isJdoModelClass(JavaClass javaClass) {
        return !javaClass.isRecord()
                && javaClass.isAnnotatedWith(PersistenceCapable.class);
    }

    private static Set<JavaClass> extractLeafTypes(JavaType type) {
        final var result = new HashSet<JavaClass>();
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

    private static void collectSwaggerSchemaImplementations(
            JavaAnnotation<?> annotation,
            JavaMethod method,
            ConditionEvents events) {
        final String annotationType = annotation.getRawType().getName();
        if (annotationType.equals(ApiResponses.class.getName())) {
            forEachNestedAnnotation(annotation, "value", inner -> collectSwaggerSchemaImplementations(inner, method, events));
        } else if (annotationType.equals(ApiResponse.class.getName())) {
            forEachNestedAnnotation(annotation, "content", inner -> collectSwaggerSchemaImplementations(inner, method, events));
        } else if (annotationType.equals(Content.class.getName())) {
            annotation.get("schema").ifPresent(value -> {
                if (value instanceof final JavaAnnotation<?> schema) {
                    checkSwaggerSchemaImplementation(schema, method, events);
                }
            });
            annotation.get("array").ifPresent(value -> {
                if (value instanceof final JavaAnnotation<?> arraySchema) {
                    arraySchema.get("schema").ifPresent(inner -> {
                        if (inner instanceof final JavaAnnotation<?> schema) {
                            checkSwaggerSchemaImplementation(schema, method, events);
                        }
                    });
                }
            });
        }
    }

    private static void checkSwaggerSchemaImplementation(
            JavaAnnotation<?> schema,
            JavaMethod method,
            ConditionEvents events) {
        schema.get("implementation").ifPresent(value -> {
            if (value instanceof final JavaClass target
                    && !target.isEquivalentTo(Void.class)
                    && isJdoModelClass(target)) {
                events.add(violated(
                        method,
                        "%s declares JDO model class %s as Swagger response schema".formatted(
                                method.getFullName(), target.getName())));
            }
        });
    }

    private static void forEachNestedAnnotation(
            JavaAnnotation<?> annotation,
            String property,
            Consumer<JavaAnnotation<?>> consumer) {
        annotation.get(property).ifPresent(value -> {
            if (value instanceof final JavaAnnotation<?>[] nested) {
                for (JavaAnnotation<?> inner : nested) {
                    consumer.accept(inner);
                }
            } else if (value instanceof final JavaAnnotation<?> single) {
                consumer.accept(single);
            }
        });
    }

}
