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
package org.owasp.dependencytrack.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

import javax.servlet.ServletContext;

/**
 * Base controller that all other controllers inherent from.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public abstract class AbstractController {

    /**
     * The ServletContext in which Dependency-Track is running in
     */
    @Autowired
    private ServletContext servletContext;

    /**
     * Spring Environment
     */
    @Autowired
    private Environment environment;

    public ServletContext getServletContext() {
        return servletContext;
    }

    public Environment getEnvironment() {
        return environment;
    }


}
