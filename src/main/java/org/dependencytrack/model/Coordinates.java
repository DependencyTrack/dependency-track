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

import org.apache.commons.lang3.StringUtils;

public class Coordinates {

    private final String group;
    private final String name;
    private final String version;

    public Coordinates(final Component component) {
        this.group = StringUtils.trimToNull(component.getGroup());
        this.name = StringUtils.trimToNull(component.getName());
        this.version = StringUtils.trimToNull(component.getVersion());
    }

    public Coordinates(final String group, final String name, final String version) {
        this.group = StringUtils.trimToNull(group);
        this.name = StringUtils.trimToNull(name);
        this.version = StringUtils.trimToNull(version);
    }

    public String getGroup() {
        return group;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }
}
