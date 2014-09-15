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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

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
     * Determine is the signup link is enabled on the login page
     */
    @Value("#{properties[signupEnabled]}")
    private String signupEnabled;

    /**
     * Determine the number of iterations when hashing a password
     */
    @Value("#{properties[hashIterations]}")
    private int hashIterations;

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

    public int getHashIterations() {
        return hashIterations;
    }

    public boolean isSignupEnabled() {
        return Boolean.parseBoolean(signupEnabled);
    }

}
