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

import java.util.ArrayList;
import java.util.List;

/*
 * Model class needed by VulnDBAnalysis task. Class brought over from the vulndb-data-mirror repo:
 * <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a>
 */
public class Version implements ApiObject {
    private int id;
    private String name;
    private boolean affected;
    private List<Cpe> cpes = new ArrayList();

    public Version() {
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

    public boolean isAffected() {
        return this.affected;
    }

    public void setAffected(boolean affected) {
        this.affected = affected;
    }

    public List<Cpe> getCpes() {
        return this.cpes;
    }

    public void setCpes(List<Cpe> cpes) {
        this.cpes = cpes;
    }

    public void addCpe(Cpe cpe) {
        this.cpes.add(cpe);
    }
}
