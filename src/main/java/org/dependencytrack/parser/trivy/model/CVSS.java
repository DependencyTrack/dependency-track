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

public class CVSS {
    @SerializedName("v2_vector")
    private String v2Vector;
    @SerializedName("v3_vector")
    private String v3Vector;
    @SerializedName("v2_score")
    private double v2Score;
    @SerializedName("v3_score")
    private double v3Score;

    public String getV2Vector() { return v2Vector; }
    public void setV2Vector(String value) { this.v2Vector = value; }

    public String getV3Vector() { return v3Vector; }
    public void setV3Vector(String value) { this.v3Vector = value; }

    public double getV2Score() { return v2Score; }
    public void setV2Score(double value) { this.v2Score = value; }

    public double getV3Score() { return v3Score; }
    public void setV3Score(double value) { this.v3Score = value; }
}