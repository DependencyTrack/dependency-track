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
package org.owasp.dependencytrack.parser.vulndb.model;

/**
 * The response from VulnDB Vulnerability API will respond with 0 or more external
 * texts. This class defines the ExternalText objects returned.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ExternalText {

    /**
     * Type of the related text ex: Solution Description.
     */
    private String type;

    /**
     * The related text ex: Currently, there are no known upgrades or patches to correct this issue.
     */
    private String value;


    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
