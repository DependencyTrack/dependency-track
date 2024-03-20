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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.parser.trivy.model;

public class OS {
    private String family;
    private String name;
    private boolean eosl;
    private boolean extended;

    public OS(){}
    public OS(String family, String name) {
        this.family = family;
        this.name = name;
    }

    public String getFamily() { return family; }
    public void setFamily(String value) { this.family = value; }

    public String getName() { return name; }
    public void setName(String value) { this.name = value; }

    public boolean getEosl() { return eosl; }
    public void setEosl(boolean value) { this.eosl = value; }

    public boolean getExtended() { return extended; }
    public void setExtended(boolean value) { this.extended = value; }
}