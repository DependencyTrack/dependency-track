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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Discriminator;
import javax.jdo.annotations.Inheritance;
import javax.jdo.annotations.InheritanceStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;

/**
 * Persistable object representing an LdapUser.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@PersistenceCapable
@Inheritance(strategy = InheritanceStrategy.SUPERCLASS_TABLE)
@Discriminator(value = "LDAP")
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(value = { "username", "dn", "email", "teams", "permissions" })
public class LdapUser extends User {

    private static final long serialVersionUID = 261924579887470488L;

    @Persistent
    @Column(name = "DN")
    @Size(min = 1, max = 255)
    @Pattern(regexp = "[\\P{Cc}]+", message = "The distinguished name must not contain control characters")
    private String dn;

    public String getDN() {
        return dn;
    }

    public void setDN(String dn) {
        this.dn = dn;
    }

}
