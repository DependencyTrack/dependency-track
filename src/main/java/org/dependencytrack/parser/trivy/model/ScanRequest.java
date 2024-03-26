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

public class ScanRequest {
    private String target;
    @SerializedName("artifact_id")
    private String artifactID;
    @SerializedName("blob_ids")
    private String[] blobIDS;
    private Options options;

    public String getTarget() { return target; }
    public void setTarget(String value) { this.target = value; }

    public String getArtifactID() { return artifactID; }
    public void setArtifactID(String value) { this.artifactID = value; }

    public String[] getBlobIDS() { return blobIDS; }
    public void setBlobIDS(String[] value) { this.blobIDS = value; }

    public Options getOptions() { return options; }
    public void setOptions(Options value) { this.options = value; }
}


