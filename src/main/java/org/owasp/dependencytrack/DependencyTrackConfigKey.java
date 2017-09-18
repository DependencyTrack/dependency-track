/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack;

import alpine.Config;

public enum DependencyTrackConfigKey implements Config.Key {

    DATASOURCE_VULN_DB_ENABLED  ("datasource.vulndb.enabled", false),
    DATASOURCE_VULN_DB_KEY      ("datasource.vulndb.key", null),
    DATASOURCE_VULN_DB_SECRET   ("datasource.vulndb.secret", null);

    private String propertyName;
    private Object defaultValue;
    DependencyTrackConfigKey(String item, Object defaultValue) {
        this.propertyName = item;
        this.defaultValue = defaultValue;
    }

    public String getPropertyName() {
        return propertyName;
    }

    public Object getDefaultValue() {
        return defaultValue;
    }

}
