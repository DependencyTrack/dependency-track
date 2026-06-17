/*
 * This file is part of Alpine.
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

package alpine.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.constraints.NotNull;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.util.UUID;

/**
 * Persistable object representing a OpenID Connect group mapped to a Team.
 *
 * @since 1.8.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@Unique(members = {"team", "group"})
public class MappedOidcGroup {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "TEAM_ID", allowsNull = "false")
    @ForeignKey(name = "MAPPEDOIDCGROUP_TEAM_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE)
    @JsonIgnore
    private Team team;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "GROUP_ID", allowsNull = "false")
    @ForeignKey(name = "MAPPEDOIDCGROUP_OIDCGROUP_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE)
    private OidcGroup group;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "MAPPEDOIDCGROUP_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(final long id) {
        this.id = id;
    }

    public Team getTeam() {
        return team;
    }

    public void setTeam(final Team team) {
        this.team = team;
    }

    public OidcGroup getGroup() {
        return group;
    }

    public void setGroup(final OidcGroup group) {
        this.group = group;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(final UUID uuid) {
        this.uuid = uuid;
    }

}
