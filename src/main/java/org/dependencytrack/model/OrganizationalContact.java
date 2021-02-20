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

import alpine.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.io.Serializable;

/**
 * Model class for tracking organizational contacts.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OrganizationalContact implements Serializable {

    private static final long serialVersionUID = -1026863376484187244L;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String name;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String email;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String phone;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }
}
