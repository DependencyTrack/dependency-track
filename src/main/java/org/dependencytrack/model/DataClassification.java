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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.io.Serializable;

/**
 * Model class for tracking data classification
 *
 * @author Steve Springett
 * @since 4.2.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataClassification implements Serializable {

    private static final long serialVersionUID = -1969199685989611696L;

    public static enum Direction {
        INBOUND("inbound"),
        OUTBOUND("outbound"),
        BI_DIRECTIONAL("bi-directional"),
        UNKNOWN("unknown");

        private final String name;

        public String getDirectionName() {
            return this.name;
        }

        private Direction(String name) {
            this.name = name;
        }
    }

    private Direction direction;
    private String name;

    public Direction getDirection() {
        return direction;
    }

    public void setDirection(Direction direction) {
        this.direction = direction;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
