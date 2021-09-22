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
package org.dependencytrack.persistence;

import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Project;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Date;
import java.util.List;

final class BomQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    BomQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    BomQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Creates a new Bom.
     * @param project the Project to create a Bom for
     * @param imported the Date when the bom was imported
     * @return a new Bom object
     */
    public Bom createBom(Project project, Date imported, Bom.Format format, String specVersion, Integer bomVersion, String serialNumber) {
        final Bom bom = new Bom();
        bom.setImported(imported);
        bom.setProject(project);
        bom.setBomFormat(format);
        bom.setSpecVersion(specVersion);
        bom.setBomVersion(bomVersion);
        bom.setSerialNumber(serialNumber);
        return persist(bom);
    }

    /**
     * Returns a list of all Bom for the specified Project.
     * @param project the Project to retrieve boms for
     * @return a List of Boms
     */
    @SuppressWarnings("unchecked")
    public List<Bom> getAllBoms(Project project) {
        final Query<Bom> query = pm.newQuery(Bom.class, "project == :project");
        return (List<Bom>) query.execute(project);
    }

    /**
     * Deletes boms belonging to the specified Project.
     * @param project the Project to delete boms for
     */
    public void deleteBoms(Project project) {
        final Query<Bom> query = pm.newQuery(Bom.class, "project == :project");
        query.deletePersistentAll(project);
    }
}
