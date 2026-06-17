/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.persistence;

import org.datanucleus.PropertyNames;

import java.util.Properties;

/**
 * This class provides runtime constants for JDO properties.
 *
 * @since 1.4.3
 */
public final class JdoProperties {

    private JdoProperties() { }

    public static Properties unit() {
        final Properties properties = new Properties();
        properties.put("javax.jdo.option.PersistenceUnitName", "Alpine");
        properties.put("javax.jdo.option.ConnectionURL", "jdbc:h2:mem:alpine;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH");
        properties.put("javax.jdo.option.ConnectionDriverName", "org.h2.Driver");
        properties.put("javax.jdo.option.ConnectionUserName", "sa");
        properties.put("javax.jdo.option.ConnectionPassword", "");
        properties.put("javax.jdo.option.Mapping", "h2");
        properties.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_DATABASE, "true");
        properties.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_TABLES, "true");
        properties.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_COLUMNS, "true");
        properties.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_CONSTRAINTS, "true");
        properties.put(PropertyNames.PROPERTY_SCHEMA_GENERATE_DATABASE_MODE, "create");
        properties.put(PropertyNames.PROPERTY_QUERY_JDOQL_ALLOWALL, "true");
        properties.put(PropertyNames.PROPERTY_CACHE_L2_TYPE, "none");
        properties.put(PropertyNames.PROPERTY_RETAIN_VALUES, "true");
        properties.put(PropertyNames.PROPERTY_METADATA_ALLOW_XML, "false");
        properties.put(PropertyNames.PROPERTY_METADATA_SUPPORT_ORM, "false");
        properties.put(PropertyNames.PROPERTY_EXECUTION_CONTEXT_MAX_IDLE, "0");
        properties.put(PropertyNames.PROPERTY_DELETION_POLICY, "DataNucleus");
        return properties;
    }
}
