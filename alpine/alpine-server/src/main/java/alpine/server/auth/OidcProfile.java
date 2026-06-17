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

package alpine.server.auth;

import java.util.List;

import net.minidev.json.JSONObject;

/**
 * @since 1.10.0
 */
public class OidcProfile {

    private String subject, username, email;
    private List<String> groups;
    private JSONObject customValues = new JSONObject();

    public String getSubject() {
        return subject;
    }

    public void setSubject(final String subject) {
        this.subject = subject;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(final List<String> groups) {
        this.groups = groups;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(final String email) {
        this.email = email;
    }

    public Object getCustomValue(final String key) {
        return customValues.get(key);
    }

    public Object putCustomValue(final String key, final Object value) {
        return customValues.put(key, value);
    }

    public JSONObject getCustomValues() {
        return customValues;
    }

    public void setCustomValues(JSONObject customValues) {
        this.customValues = customValues;
    }

    @Override
    public String toString() {
        return "%s{subject='%s', username='%s', groups=%s, email='%s', customValues=%s".formatted(
                getClass().getSimpleName(), subject, username, groups, email, customValues);
    }

}
