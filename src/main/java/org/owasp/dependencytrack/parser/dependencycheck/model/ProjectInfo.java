/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
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
