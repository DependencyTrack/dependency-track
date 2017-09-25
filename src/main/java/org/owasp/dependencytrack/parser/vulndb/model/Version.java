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

import java.util.ArrayList;
import java.util.List;

/**
 * The response from VulnDB Version API will respond with 0 or more versions.
 * This class defines the Version objects returned.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class Version {

    private int id;
    private String name;
    private boolean affected;
    private List<CPE> cpes = new ArrayList<>();

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isAffected() {
        return affected;
    }

    public void setAffected(boolean affected) {
        this.affected = affected;
    }

    public List<CPE> getCpes() {
        return cpes;
    }

    public void setCpes(List<CPE> cpes) {
        this.cpes = cpes;
    }

    public void addCpe(CPE cpe) {
        this.cpes.add(cpe);
    }
}
