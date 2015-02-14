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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */
package org.owasp.dependencytrack;

import org.owasp.dependencytrack.model.Roles;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicReference;

/**
 * A Configuration class that maps Java methods to keys in application.properties.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Component
public final class Config {

    /**
     * The short name of the application
     */
    @Value("#{properties[shortname]}")
    private String shortname;

    /**
     * The long name of the application
     */
    @Value("#{properties[longname]}")
    private String longname;

    /**
     * The version of application
     */
    @Value("#{properties[version]}")
    private String version;

    /**
     * The date in which the application was built
     */
    @Value("#{properties[builddate]}")
    private String buildDate;

    /**
     * The number of Bcrypt rounds to use when hashing passwords
     */
    @Value("#{properties[bcryptRounds]}")
    private Integer bcryptRounds;

    /**
     * The default role to use for authenticated user without role mappings
     */
    @Value("#{properties[defaultUserRole]}")
    private String defaultUserRole;

    /**
     * The optional application home directory to use
     */
    @Value("#{properties[appHome]}")
    private String appHome;

    /**
     * Holds a reference to the singleton instance
     */
    private static final AtomicReference<Config> INSTANCE = new AtomicReference<>();

    /**
     * Spring bean initialization should only call this constructor. By definition, this
     * component is a singleton.
     */
    public Config() {
        final Config previous = INSTANCE.getAndSet(this);
        if (previous != null) {
            throw new IllegalStateException("Second singleton " + this + " created after " + previous);
        }
    }

    /**
     * If manual (non autowired) access to this class is required, this will
     * return the singleton instance.
     * @return a Config object
     */
    public static Config getInstance() {
        return INSTANCE.get();
    }

    public String getShortname() {
        return shortname;
    }

    public String getLongname() {
        return longname;
    }

    public String getVersion() {
        return version;
    }

    public String getBuildDate() {
        return buildDate;
    }

    public Integer getBcryptRounds() {
        return bcryptRounds;
    }

    public Roles.ROLE getDefaultRole() {
        return Roles.ROLE.getRole(defaultUserRole);
    }

    public String getAppHome() {
        return appHome;
    }
}
