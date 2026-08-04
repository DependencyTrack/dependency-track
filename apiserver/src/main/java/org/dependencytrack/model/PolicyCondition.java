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
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.UUID;

/**
 * Defines a Model class for defining a policy condition.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PolicyCondition implements Serializable {

    public enum Operator {
        IS,
        IS_NOT,
        MATCHES,
        NO_MATCH,
        NUMERIC_GREATER_THAN,
        NUMERIC_LESS_THAN,
        NUMERIC_EQUAL,
        NUMERIC_NOT_EQUAL,
        NUMERIC_GREATER_THAN_OR_EQUAL,
        NUMERIC_LESSER_THAN_OR_EQUAL,
        CONTAINS_ALL,
        CONTAINS_ANY
    }

    public enum Subject {
        AGE(PolicyViolation.Type.OPERATIONAL),
        //ANALYZER,
        //BOM,
        COORDINATES(PolicyViolation.Type.OPERATIONAL),
        CPE(PolicyViolation.Type.OPERATIONAL),
        //INHERITED_RISK_SCORE,
        EXPRESSION(null),
        LICENSE(PolicyViolation.Type.LICENSE),
        LICENSE_GROUP(PolicyViolation.Type.LICENSE),
        PACKAGE_URL(PolicyViolation.Type.OPERATIONAL),
        SEVERITY(PolicyViolation.Type.SECURITY),
        SWID_TAGID(PolicyViolation.Type.OPERATIONAL),
        VERSION(PolicyViolation.Type.OPERATIONAL),
        COMPONENT_HASH(PolicyViolation.Type.OPERATIONAL),
        IS_INTERNAL(PolicyViolation.Type.OPERATIONAL),
        CWE(PolicyViolation.Type.SECURITY),
        VULNERABILITY_ID(PolicyViolation.Type.SECURITY),
        VERSION_DISTANCE(PolicyViolation.Type.OPERATIONAL),
        EPSS(PolicyViolation.Type.SECURITY);

        private final PolicyViolation.Type violationType;

        Subject(final PolicyViolation.Type violationType) {
            this.violationType = violationType;
        }
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @ForeignKey(name = "POLICYCONDITION_POLICY_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "POLICY_ID", allowsNull = "false")
    private Policy policy;

    @Persistent
    @Column(name = "OPERATOR", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The operator may only contain printable characters")
    private Operator operator;

    @Persistent
    @Column(name = "SUBJECT", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The subject may only contain printable characters")
    private Subject subject;

    @Persistent
    @Column(name = "VALUE", allowsNull = "false", jdbcType = "CLOB")
    @NotBlank
    @Size(min = 1)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The value may only contain printable characters")
    private String value;

    @Persistent
    @Column(name = "VIOLATIONTYPE", allowsNull = "true")
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The violation type may only contain printable characters")
    private PolicyViolation.Type violationType;

    /**
     * The unique identifier of the object.
     */
    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "POLICYCONDITION_UUID_IDX")
    @Column(name = "UUID", sqlType = "UUID", allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public Operator getOperator() {
        return operator;
    }

    public void setOperator(Operator operator) {
        this.operator = operator;
    }

    public Subject getSubject() {
        return subject;
    }

    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public PolicyViolation.Type getViolationType() {
        if (subject != null && subject.violationType != null) {
            return subject.violationType;
        }

        return violationType;
    }

    public void setViolationType(PolicyViolation.Type violationType) {
        this.violationType = violationType;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
