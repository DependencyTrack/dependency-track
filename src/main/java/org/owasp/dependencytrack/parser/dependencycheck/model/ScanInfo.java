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
