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
package org.dependencytrack.parser.trivy.model;

import com.google.gson.annotations.SerializedName;

public class Package {
    private String name;
    private String version;
    private String arch;

    @SerializedName("src_name")
    private String srcName;
    @SerializedName("src_version")
    private String srcVersion;
    private String[] licenses;
    private OS layer;

    public Package(String name, String version, String arch) {
        this.name = name;
        this.version = version;
        this.arch = arch;

        this.srcName = name;
        this.srcVersion = version;

        this.licenses = new String[] {};
        this.layer = new OS();
    }

    public String getName() { return name; }
    public void setName(String value) { this.name = value; }

    public String getVersion() { return version; }
    public void setVersion(String value) { this.version = value; }

    public String getArch() { return arch; }
    public void setArch(String value) { this.arch = value; }

    public String getSrcName() { return srcName; }
    public void setSrcName(String value) { this.srcName = value; }

    public String getSrcVersion() { return srcVersion; }
    public void setSrcVersion(String value) { this.srcVersion = value; }

    public String[] getLicenses() { return licenses; }
    public void setLicenses(String[] value) { this.licenses = value; }

    public OS getLayer() { return layer; }
    public void setLayer(OS value) { this.layer = value; }
}