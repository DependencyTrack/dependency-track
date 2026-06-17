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

import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.sqlobject.customizer.SqlStatementCustomizer;
import org.jdbi.v3.sqlobject.customizer.SqlStatementCustomizerFactory;
import org.jdbi.v3.sqlobject.customizer.SqlStatementCustomizingAnnotation;

import java.lang.annotation.Annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.sql.PreparedStatement;

import static org.dependencytrack.persistence.jdbi.ApiRequestStatementCustomizer.PARAMETER_PROJECT_ACL_API_KEY_ID;
import static org.dependencytrack.persistence.jdbi.ApiRequestStatementCustomizer.PARAMETER_PROJECT_ACL_USER_ID;
import static org.dependencytrack.persistence.jdbi.ApiRequestStatementCustomizer.TEMPLATE_API_KEY_PROJECT_ACL_CONDITION;
import static org.dependencytrack.persistence.jdbi.ApiRequestStatementCustomizer.TEMPLATE_USER_PROJECT_ACL_CONDITION;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION;

/**
 * @since 5.0.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@SqlStatementCustomizingAnnotation(DefineApiProjectAclCondition.StatementCustomizerFactory.class)
public @interface DefineApiProjectAclCondition {

    /**
     * @return Name of the attribute to define the condition as
     */
    String name() default JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION;

    /**
     * @return Alias of the {@code PROJECT} table to use in the condition
     */
    String projectIdColumn();

    final class StatementCustomizerFactory implements SqlStatementCustomizerFactory {

        @Override
        public SqlStatementCustomizer createForMethod(
                final Annotation annotation,
                final Class<?> sqlObjectType,
                final Method method
        ) {
            return statement -> {
                if (!(annotation instanceof final DefineApiProjectAclCondition defineAnnotation)) {
                    return;
                }

                final String attributeName = defineAnnotation.name().trim();
                if (attributeName.isEmpty()) {
                    throw new IllegalArgumentException("name must not be blank");
                }

                final String projectIdColumn = defineAnnotation.projectIdColumn().trim();
                if (projectIdColumn.isEmpty()) {
                    throw new IllegalArgumentException("project id column must not be blank");
                }

                statement.addCustomizer(new StatementCustomizer(attributeName, projectIdColumn));
            };
        }

    }

    final class StatementCustomizer implements org.jdbi.v3.core.statement.StatementCustomizer {

        private final String attributeName;
        private final String projectIdColumn;

        public StatementCustomizer(final String attributeName, final String projectIdColumn) {
            this.attributeName = attributeName;
            this.projectIdColumn = projectIdColumn;
        }

        @Override
        @SuppressWarnings("removal") // Binding#findForName is the only way to inspect bindings.
        public void beforeTemplating(final PreparedStatement stmt, final StatementContext ctx) {
            if (!(ctx.getAttribute(ATTRIBUTE_API_PROJECT_ACL_CONDITION) instanceof final String aclCondition)) {
                // No condition was defined by ApiRequestStatementCustomizer; Nothing to do.
                return;
            }

            // Ensure that the chosen table alias doesn't overlap with the one used
            // in the condition defined by ApiRequestStatementCustomizer.
            final var apiRequestConfig = ctx.getConfig(ApiRequestConfig.class);
            final String defaultProjectIdColumn = apiRequestConfig.projectAclProjectIdColumn();
            if (projectIdColumn.equals(defaultProjectIdColumn)) {
                throw new IllegalArgumentException("project id column must be different from default column name");
            }

            if (ctx.getBinding().findForName(PARAMETER_PROJECT_ACL_API_KEY_ID, ctx).isPresent()) {
                // The existing condition has defined an API key ID for the ACL check already,
                // so it's not a trivial TRUE or FALSE. Re-use that binding by defining
                // a new condition, using the chosen project table alias.
                ctx.define(attributeName, TEMPLATE_API_KEY_PROJECT_ACL_CONDITION.formatted(projectIdColumn));
            } else if (ctx.getBinding().findForName(PARAMETER_PROJECT_ACL_USER_ID, ctx).isPresent()) {
                // The existing condition has defined a user ID for the ACL check already,
                // so it's not a trivial TRUE or FALSE. Re-use that binding by defining
                // a new condition, using the chosen project table alias.
                ctx.define(attributeName, TEMPLATE_USER_PROJECT_ACL_CONDITION.formatted(projectIdColumn));
            } else {
                // Likely a trivial TRUE or FALSE; Just re-use it.
                ctx.define(attributeName, aclCondition);
            }
        }

    }

}
