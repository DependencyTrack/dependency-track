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

import com.google.gson.annotations.SerializedName;

public class Package {
    private String name;
    private String version;
    private String arch;
    private Integer epoch;

    @SerializedName("src_name")
    private String srcName;
    @SerializedName("src_version")
    private String srcVersion;
    @SerializedName("src_epoch")
    private Integer srcEpoch;
    @SerializedName("src_release")
    private String srcRelease;
    private String[] licenses;
    private OS layer;

    public Package(String name, String version, String arch, Integer epoch, String srcName, String srcVersion, String srcRelease) {

        this.name = name;
        this.version = version;
        this.arch = arch;
        this.epoch = epoch;

        this.srcName = (srcName == null) ? name : srcName;
        this.srcVersion = (srcVersion == null) ? version : srcVersion;
        this.srcEpoch = epoch;
        this.srcRelease = srcRelease;

        this.licenses = new String[] {};
        this.layer = new OS();
    }


}