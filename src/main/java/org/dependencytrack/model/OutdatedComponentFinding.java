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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The OutdatedComponentFinding object is a metadata/value object that combines data from multiple tables. 
 * The object can only be queried on, not updated or deleted. Modifications to data in the Finding object
 * need to be made to the original source object needing modified.
 *
 * @since 3.1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
// TODO OutdatedComponentFinding and Finding shoud share a common interface so both can treated equally 
// for example by the ProjectFindingUploader
public class OutdatedComponentFinding implements Serializable { 

    private static final long serialVersionUID = 1L;

    /*
     * This statement works on Microsoft SQL Server, MySQL, and PostgreSQL. Due to the standardization
     * of upper-case table and column names in Dependency-Track, every identifier needs to be wrapped
     * in double quotes to satisfy PostgreSQL case-sensitive requirements. This also places a requirement
     * on ANSI_QUOTES mode being enabled in MySQL. SQL Server works regardless and is just happy to be invited :-)
     */
    public static final String QUERY = "SELECT " +
            "\"COMPONENT\".\"UUID\"," +
            "\"COMPONENT\".\"NAME\"," +
            "\"COMPONENT\".\"GROUP\"," +
            "\"COMPONENT\".\"VERSION\"," +
            "\"COMPONENT\".\"PURL\"," +
            "\"COMPONENT\".\"CPE\"," +
            "FROM \"COMPONENT\" " +
            "WHERE \"COMPONENT\".\"PROJECT_ID\" = ? " +
            "AND \"COMPONENT\".\"PARENT_COMPONENT_ID\" IS NULL";

    private UUID project;
    private Map<String, Object> component = new LinkedHashMap<>();

    /**
     * Constructs a new OutdatedComponentFinding object. The generic Object array passed as
     * an argument is the individual values for each row in a resultset. The order of these
     * must match the order of the columns being queried in {@link #QUERY}.
     * @param o An array of values specific to an individual row returned from {@link #QUERY}
     */
    public OutdatedComponentFinding(UUID project, Object... o) {
        this.project = project;
        optValue(component, "uuid", o[0]);
        optValue(component, "name", o[1]);
        optValue(component, "group", o[2]);
        optValue(component, "version", o[3]);
        optValue(component, "purl", o[4]);
        optValue(component, "cpe", o[5]);
        optValue(component, "project", project.toString());
    }

    public UUID getProject() {
        return project;
    }
    
    public Map<String, Object> getComponent() {
        return component;
    }

    private void optValue(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

}
