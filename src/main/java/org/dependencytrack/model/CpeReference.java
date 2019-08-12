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

import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.Objects;

/**
 * Model class for CPE References.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CpeReference implements Serializable {

    private static final long serialVersionUID = -2728964127993930018L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "CPE_ID")
    private Cpe cpe;

    @Persistent
    @Column(name = "NAME", jdbcType = "VARCHAR")
    @Size(max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "HREF", jdbcType = "VARCHAR", length = 2048)
    @Size(max = 2048)
    @Pattern(regexp = RegexSequence.Definition.HTTP_URI, message = "The href may only contain a valid URI")
    private String href;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Cpe getCpe() {
        return cpe;
    }

    public void setCpe(Cpe cpe) {
        this.cpe = cpe;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getHref() {
        return href;
    }

    public void setHref(String href) {
        this.href = href;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CpeReference)) return false;
        CpeReference reference = (CpeReference) o;
        return id == reference.id &&
                Objects.equals(cpe, reference.cpe) &&
                Objects.equals(name, reference.name) &&
                Objects.equals(href, reference.href);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, cpe, name, href);
    }
}
