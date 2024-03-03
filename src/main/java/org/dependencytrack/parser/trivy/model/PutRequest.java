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

public class PutRequest {
    @SerializedName("diff_id")
    private String diffID;
    @SerializedName("blob_info")
    private BlobInfo blobInfo;

    public String getDiffID() { return diffID; }
    public void setDiffID(String value) { this.diffID = value; }

    public BlobInfo getBlobInfo() { return blobInfo; }
    public void setBlobInfo(BlobInfo value) { this.blobInfo = value; }
}
