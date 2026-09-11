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
package alpine.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Discriminator;
import javax.jdo.annotations.Inheritance;
import javax.jdo.annotations.InheritanceStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;

/// @since 5.2.0
@PersistenceCapable
@Inheritance(strategy = InheritanceStrategy.SUPERCLASS_TABLE)
@Discriminator(value = "SERVICE")
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(value = {"username", "email", "suspended", "teams", "permissions"})
public class ServiceAccount extends User {

    public static final String USERNAME_PREFIX = "svc-";

    @Persistent
    @Column(name = "SUSPENDED")
    private boolean suspended;

    public static boolean hasReservedPrefix(String username) {
        return username.regionMatches(/* ignoreCase */ true, 0, USERNAME_PREFIX, 0, USERNAME_PREFIX.length());
    }

    public static String nameOf(String username) {
        return username.substring(USERNAME_PREFIX.length());
    }

    public static String usernameOf(String name) {
        return USERNAME_PREFIX + name;
    }

    public boolean isSuspended() {
        return suspended;
    }

    public void setSuspended(boolean suspended) {
        this.suspended = suspended;
    }
}
