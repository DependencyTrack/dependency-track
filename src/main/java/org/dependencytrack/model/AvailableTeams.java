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

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AvailableTeams implements Serializable {
  private boolean required;
  private List<LittleTeam> teams;

  public boolean isRequired() {
    return required;
  }

  public void setRequired(final boolean required) {
    this.required = required;
  }

  public List<LittleTeam> getTeams() {
    return teams;
  }

  public void setTeams(final List<LittleTeam> teams) {
    this.teams = teams;
  }

  @Override
  public String toString() {
    List<String> strlistTeams = teams.stream()
        .map(Object::toString)
        .toList();
    String strTeams = String.join(",", strlistTeams);
    return String.format("required: %s, teams: [ %s ]", required, strTeams);
  }

}
