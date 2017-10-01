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
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Date;

/**
 * Defines the projectInfo element in a Dependency-Check report.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@XmlRootElement(name = "projectInfo")
public class ProjectInfo extends BaseObject {

    private String name;
    private Date reportDate;
    private String credits;

    public String getName() {
        return name;
    }

    @XmlElement(name = "name")
    public void setName(String name) {
        this.name = normalize(name);
    }

    public Date getReportDate() {
        return reportDate;
    }

    @XmlElement(name = "reportDate")
    @XmlJavaTypeAdapter(DateAdapter.class)
    public void setReportDate(Date reportDate) {
        this.reportDate = reportDate;
    }

    public String getCredits() {
        return credits;
    }

    @XmlElement(name = "credits")
    public void setCredits(String credits) {
        this.credits = normalize(credits);
    }
}
