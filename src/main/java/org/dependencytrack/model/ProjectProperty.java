/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import alpine.model.ConfigProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Inheritance;
import javax.jdo.annotations.InheritanceStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;

/**
 * User-defined key/value model for individual projects.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@PersistenceCapable(table = "PROJECT_PROPERTY")
@Inheritance(strategy = InheritanceStrategy.COMPLETE_TABLE)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProjectProperty extends ConfigProperty {

    private static final long serialVersionUID = 7394616773695958262L;

    @Persistent
    @Column(name = "PROJECT_ID", allowsNull = "false")
    private Project project;

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

}
