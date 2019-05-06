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

import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import javax.validation.constraints.Pattern;

/**
 * Defines a custom request object used when adding a new MappedLdapGroup.
 *
 * @author Steve Springett
 * @since 3.3.0
 */
public class MappedLdapGroupRequest {

    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The team must be a valid 36 character UUID")
    private String team;

    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS, message = "The dn may only contain printable characters")
    private String dn;

    @JsonCreator
    public MappedLdapGroupRequest(
            @JsonProperty(value = "team", required = true) String team,
            @JsonProperty(value = "dn", required = true) String dn) {
        this.team = team;
        this.dn = dn;
    }

    public String getTeam() {
        return team;
    }

    public void setTeam(String team) {
        this.team = team;
    }

    public String getDn() {
        return dn;
    }

    public void setDn(String dn) {
        this.dn = dn;
    }
}
