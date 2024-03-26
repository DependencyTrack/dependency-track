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

public class BlobInfo {
    @SerializedName("schema_version")
    private long schemaVersion;
    private OS os;
    private Application[] applications;
    @SerializedName("package_infos")
    private PackageInfo[] packageInfos;

    public BlobInfo() {
        this.schemaVersion = 2;
        this.os = new OS();
    }

    public long getSchemaVersion() { return schemaVersion; }
    public void setSchemaVersion(long value) { this.schemaVersion = value; }

    public OS getOS() { return os; }
    public void setOS(OS value) { this.os = value; }

    public Application[] getApplications() { return applications; }
    public void setApplications(Application[] value) { this.applications = value; }

    public PackageInfo[] getPackageInfos() { return packageInfos; }
    public void setPackageInfos(PackageInfo[] value) { this.packageInfos = value; }
}
