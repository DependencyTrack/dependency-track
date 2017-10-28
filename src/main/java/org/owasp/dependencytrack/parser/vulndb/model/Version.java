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
package org.owasp.dependencytrack.parser.vulndb.model;

import java.util.ArrayList;
import java.util.List;

/**
 * The response from VulnDB Version API will respond with 0 or more versions.
 * This class defines the Version objects returned.
 *
 * @author Steve Springett
 * @since 3.0.0
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
