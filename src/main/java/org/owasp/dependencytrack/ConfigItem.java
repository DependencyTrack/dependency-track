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

/**
 * This class provides a statically typed way to specify the named pairs
 * in a property file. All names which have a corresponding value in the
 * property file should be added to the enum.
 * Refer to {@link Config#getProperty(ConfigItem) Config.getProperty}
 */
public enum	ConfigItem {

    APPLICATION_NAME("application.name"),
    APPLICATION_VERSION("application.version"),
    APPLICATION_TIMESTAMP("application.timestamp"),

    DATABASE_MODE("database.mode"),
    DATABASE_PORT("database.port"),

    ENFORCE_AUTHENTICATION("enforce.authentication"),
    ENFORCE_AUTHORIZATION("enforce.authorization"),

    LDAP_SERVER_URL("ldap.server.url"),
    LDAP_DOMAIN("ldap.domain");

    String propertyName;
    private ConfigItem(String item) {
        this.propertyName = item;
    }

}