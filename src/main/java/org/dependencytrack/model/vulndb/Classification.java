/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model.vulndb;

/*
 * Model class needed by VulnDBAnalysis task. Class brought over from the vulndb-data-mirror repo:
 * <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a>
 */
public class Classification {
    private int id;
    private String name;
    private String longname;
    private String description;
    private String mediumtext;

    public Classification() {
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLongname() {
        return this.longname;
    }

    public void setLongname(String longname) {
        this.longname = longname;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getMediumtext() {
        return this.mediumtext;
    }

    public void setMediumtext(String mediumtext) {
        this.mediumtext = mediumtext;
    }
}
