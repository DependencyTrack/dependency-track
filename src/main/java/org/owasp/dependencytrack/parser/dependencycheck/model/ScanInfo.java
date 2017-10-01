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
package org.owasp.dependencytrack.parser.dependencycheck.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 * Defines the scanInfo element in a Dependency-Check report.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@XmlRootElement(name = "scanInfo")
public class ScanInfo extends BaseObject {

    private String engineVersion;
    private List<DataSource> dataSources;


    public String getEngineVersion() {
        return engineVersion;
    }

    @XmlElement(name = "engineVersion")
    public void setEngineVersion(String engineVersion) {
        this.engineVersion = normalize(engineVersion);
    }

    public List<DataSource> getDataSources() {
        return dataSources;
    }

    @XmlElement(name = "dataSource")
    public void setDataSources(List<DataSource> dataSources) {
        this.dataSources = dataSources;
    }
}
