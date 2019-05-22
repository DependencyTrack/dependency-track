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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Defines a custom response object used when querying a token for processing status.
 *
 * @author Justin Tay
 * @since 3.5.0
 */
public final class TokenBeingProcessedResponse {

    private final boolean processing;

    @JsonCreator
    public TokenBeingProcessedResponse(@JsonProperty(value = "processing", required = true) boolean processing) {
    	this.processing = processing;
    }

	public boolean isProcessing() {
		return processing;
	}
}
