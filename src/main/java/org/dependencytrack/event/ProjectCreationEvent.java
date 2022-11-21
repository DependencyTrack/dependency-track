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
package org.dependencytrack.event;

import alpine.event.framework.AbstractChainableEvent;

import java.util.UUID;

/**
 * Defines an event triggered when a new project is created.
 *
 * @author Mark Zeman
 * @since 4.6.x
 */
public class ProjectCreationEvent extends AbstractChainableEvent {

  private final UUID projectUuid;
  private final String projectName;
  
  public ProjectCreationEvent(final UUID projectUuid, final String projectName){
    this.projectUuid = projectUuid;
    this.projectName = projectName;
  }

  public UUID getProjectUuid() {
    return projectUuid;
  }

  public String getProjectName(){
    return projectName;
  }
}
