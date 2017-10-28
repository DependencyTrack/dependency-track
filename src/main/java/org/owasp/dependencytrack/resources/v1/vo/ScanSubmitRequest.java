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
package org.owasp.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

/**
 * Defines a custom request object used when uploading Dependency-Check scans.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ScanSubmitRequest {

    @NotNull
    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The project must be a valid 36 character UUID")
    private final String project;

    @NotNull
    @Pattern(regexp = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", message = "Scan must be Base64 encoded")
    private final String scan;

    @JsonCreator
    public ScanSubmitRequest(@JsonProperty(value = "project", required = true) String project,
                             @JsonProperty(value = "scan", required = true) String scan) {
        this.project = project;
        this.scan = scan;
    }

    public String getProject() {
        return project;
    }

    public String getScan() {
        return scan;
    }

}
