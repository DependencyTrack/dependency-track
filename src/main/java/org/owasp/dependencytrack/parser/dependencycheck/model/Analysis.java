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
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 * Defines the top-level Analysis object in a Dependency-Check report.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@XmlRootElement(name = "analysis")
public class Analysis extends BaseObject {

    private ScanInfo scanInfo;
    private ProjectInfo projectInfo;
    private List<Dependency> dependencies;

    public ScanInfo getScanInfo() {
        return scanInfo;
    }

    @XmlElement(name = "scanInfo")
    public void setScanInfo(ScanInfo scanInfo) {
        this.scanInfo = scanInfo;
    }

    public ProjectInfo getProjectInfo() {
        return projectInfo;
    }

    @XmlElement(name = "projectInfo")
    public void setProjectInfo(ProjectInfo projectInfo) {
        this.projectInfo = projectInfo;
    }

    public List<Dependency> getDependencies() {
        return dependencies;
    }

    @XmlElementWrapper(name = "dependencies")
    @XmlElement(name = "dependency")
    public void setDependencies(List<Dependency> dependencies) {
        this.dependencies = dependencies;
    }
}
