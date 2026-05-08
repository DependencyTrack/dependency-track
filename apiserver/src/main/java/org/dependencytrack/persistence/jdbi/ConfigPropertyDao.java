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

import alpine.model.ConfigProperty;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindBean;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * @since 5.0.0
 */
public interface ConfigPropertyDao extends SqlObject {

    @SqlQuery("""
            SELECT *
              FROM "CONFIGPROPERTY"
             WHERE "GROUPNAME" = :group
               AND "PROPERTYNAME" = :name
            """)
    @RegisterBeanMapper(ConfigProperty.class)
    Optional<ConfigProperty> getOptional(@Bind String group, @Bind String name);

    default Optional<String> getOptionalRawValue(@BindBean ConfigPropertyConstants property) {
        return getOptional(property.getGroupName(), property.getPropertyName())
                .map(ConfigProperty::getPropertyValue);
    }

    default Optional<String> getOptionalValue(final ConfigPropertyConstants property) {
        return getOptionalRawValue(property);
    }

    default <T> Optional<T> getOptionalValue(final ConfigPropertyConstants property, final Class<T> clazz) {
        final Optional<String> optionalStringValue = getOptionalValue(property);
        if (optionalStringValue.isEmpty()) {
            return Optional.empty();
        }

        final T convertedValue;

        // Add more conversions as needed.
        if (clazz.isAssignableFrom(CharSequence.class)) {
            convertedValue = clazz.cast(optionalStringValue.get());
        } else if (clazz.isAssignableFrom(String.class)) {
            convertedValue = clazz.cast(optionalStringValue.get());
        } else if (clazz.isAssignableFrom(Boolean.class)) {
            convertedValue = clazz.cast(Boolean.parseBoolean(optionalStringValue.get()));
        } else if (clazz.isAssignableFrom(Integer.class)) {
            convertedValue = clazz.cast(Integer.parseInt(optionalStringValue.get()));
        } else if (clazz.isAssignableFrom(Long.class)) {
            convertedValue = clazz.cast(Long.parseLong(optionalStringValue.get()));
        } else {
            throw new IllegalArgumentException("Cannot convert to %s".formatted(clazz.getName()));
        }

        return Optional.of(convertedValue);
    }

    default <T> T getValue(final ConfigPropertyConstants property, final Class<T> clazz) {
        return getOptionalValue(property, clazz).orElseThrow(NoSuchElementException::new);
    }

    @SqlUpdate("""
            UPDATE "CONFIGPROPERTY"
               SET "PROPERTYVALUE" = :value
             WHERE "GROUPNAME" = :group
               AND "PROPERTYNAME" = :name
            """)
    boolean setValue(@Bind String group, @Bind String name, @Bind String value);

    default void setValue(@BindBean ConfigPropertyConstants property, @Bind String value) {
        setValue(property.getGroupName(), property.getPropertyName(), value);
    }

}
