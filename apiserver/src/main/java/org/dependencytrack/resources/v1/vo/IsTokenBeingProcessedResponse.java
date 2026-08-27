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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.jspecify.annotations.Nullable;

import java.io.Serializable;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IsTokenBeingProcessedResponse implements Serializable {

    private static final long serialVersionUID = -7592468766586686855L;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private Boolean processing;

    @Schema(
            nullable = true,
            description = "The processing status associated with the token. "
                    + "Null when no processing is associated with the token.")
    @Nullable
    private Status status;

    public void setProcessing(Boolean processing) {
        this.processing = processing;
    }

    public Boolean getProcessing() {
        return this.processing;
    }

    public void setStatus(@Nullable Status status) {
        this.status = status;
    }

    @Nullable
    public Status getStatus() {
        return this.status;
    }

    public enum Status {
        PENDING,
        RUNNING,
        COMPLETED,
        FAILED;

        public static Status of(final WorkflowRunStatus runStatus) {
            return switch (runStatus) {
                case CREATED, SUSPENDED -> PENDING;
                case RUNNING -> RUNNING;
                case COMPLETED -> COMPLETED;
                case CANCELLED, FAILED -> FAILED;
            };
        }
    }
}
