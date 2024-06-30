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
package org.dependencytrack.model;

import alpine.common.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Defines a Model class for defining a policy.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Policy implements Serializable {

    public enum Operator {
        ALL,
        ANY
    }

    public enum ViolationState {
        INFO,
        WARN,
        FAIL
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    /**
     * The String representation of the policy name.
     */
    @Persistent
    @Column(name = "NAME", allowsNull = "false")
    @Index(name = "POLICY_NAME_IDX")
    @NotBlank
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    /**
     * The operator to use when evaluating conditions.
     */
    @Persistent
    @Column(name = "OPERATOR", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The operator may only contain printable characters")
    private Operator operator;

    /**
     * The state the policy should trigger upon violation.
     */
    @Persistent
    @Column(name = "VIOLATIONSTATE", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The operator may only contain printable characters")
    private ViolationState violationState;

    /**
     * A list of zero-to-n policy conditions.
     */
    @Persistent(mappedBy = "policy", defaultFetchGroup = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<PolicyCondition> policyConditions;

    /**
     * A list of zero-to-n projects
     */
    @Persistent(table = "POLICY_PROJECTS", defaultFetchGroup = "true")
    @Join(column = "POLICY_ID")
    @Element(column = "PROJECT_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC, version ASC"))
    private List<Project> projects;

    /**
     * A list of zero-to-n tags
     */
    @Persistent(table = "POLICY_TAGS", defaultFetchGroup = "true", mappedBy = "policies")
    @Join(column = "POLICY_ID")
    @Element(column = "TAG_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC"))
    private List<Tag> tags;

    /**
     * The unique identifier of the object.
     */
    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "POLICY_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    /**
     * Include the children of the projects in the policy evaluation.
     */
    @Persistent
    @Column(name = "INCLUDE_CHILDREN", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private boolean includeChildren;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Operator getOperator() {
        return operator;
    }

    public void setOperator(Operator operator) {
        this.operator = operator;
    }

    public ViolationState getViolationState() {
        return violationState;
    }

    public void setViolationState(ViolationState violationState) {
        this.violationState = violationState;
    }

    public List<PolicyCondition> getPolicyConditions() {
        return policyConditions;
    }

    public void setPolicyConditions(List<PolicyCondition> policyConditions) {
        this.policyConditions = policyConditions;
    }

    public void addPolicyCondition(PolicyCondition policyCondition) {
        if (this.policyConditions == null) {
            this.policyConditions = new ArrayList<>();
        }
        this.policyConditions.add(policyCondition);
    }

    public List<Project> getProjects() {
        return projects;
    }

    public void setProjects(List<Project> projects) {
        this.projects = projects;
    }

    public boolean isGlobal() {
        return (projects == null || projects.size() == 0) && (tags == null || tags.size() == 0);
    }

    public List<Tag> getTags() {
        return tags;
    }

    public void setTags(List<Tag> tags) {
        this.tags = tags;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public boolean isIncludeChildren() {
        return includeChildren;
    }

    public void setIncludeChildren(boolean includeChildren) {
        this.includeChildren = includeChildren;
    }
}
