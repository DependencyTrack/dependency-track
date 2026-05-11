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

import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.extension.SimpleExtensionConfigurer;
import org.jdbi.v3.core.extension.annotation.UseExtensionConfigurer;

import java.lang.annotation.Annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.trimToNull;

/**
 * @since 5.0.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@UseExtensionConfigurer(AllowApiOrdering.ExtensionConfigurer.class)
public @interface AllowApiOrdering {

    /**
     * Columns to allow ordering by.
     */
    Column[] by();

    /**
     * Name of the column that should always be included in the {@code ORDER BY}
     * clause. A corresponding {@link Column} must be provided to {@link #by()}.
     * <p>
     * Can optionally include the ordering direction as {@code asc} or {@code desc}.
     */
    String alwaysBy() default "";

    @Documented
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @interface Column {

        /**
         * Name of the column to allow ordering by.
         * <p>
         * It will be quoted automatically with double quotes before insertion to the query.
         */
        String name();

        /**
         * An optional, <strong>raw</strong> name of the column, as used in the query.
         * <p>
         * When provided, this name will be used instead of {@link #name()},
         * when ordering by a column matching {@link #name()} is requested.
         * <p>
         * This name will not be quoted automatically.
         */
        String queryName() default "";

    }

    final class ExtensionConfigurer extends SimpleExtensionConfigurer {

        @Override
        public void configure(final ConfigRegistry configRegistry, final Annotation annotation, final Class<?> extensionType) {
            final var allowOrderingAnnotation = (AllowApiOrdering) annotation;

            final var config = configRegistry.get(ApiRequestConfig.class);
            config.setOrderingAlwaysBy(allowOrderingAnnotation.alwaysBy());
            config.setOrderingAllowedColumns(Arrays.stream(allowOrderingAnnotation.by())
                    .map(column -> new ApiRequestConfig.OrderingColumn(
                            column.name(),
                            trimToNull(column.queryName())
                    ))
                    .collect(Collectors.toSet()));
        }

    }

}
