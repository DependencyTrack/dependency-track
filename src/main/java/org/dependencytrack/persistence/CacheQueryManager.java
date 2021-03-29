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
import org.dependencytrack.model.ComponentAnalysisCache;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.json.JsonObject;
import java.util.Date;

public class CacheQueryManager extends QueryManager implements IQueryManager {


    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    CacheQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    CacheQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public ComponentAnalysisCache getComponentAnalysisCache(ComponentAnalysisCache.CacheType cacheType, String targetHost, String targetType, String target) {
        final Query<ComponentAnalysisCache> query = pm.newQuery(ComponentAnalysisCache.class,
                "cacheType == :cacheType && targetHost == :targetHost && targetType == :targetType && target == :target");
        query.setOrdering("lastOccurrence desc");
        return singleResult(query.executeWithArray(cacheType, targetHost, targetType, target));
    }

    public synchronized void updateComponentAnalysisCache(ComponentAnalysisCache.CacheType cacheType, String targetHost, String targetType, String target, Date lastOccurrence, JsonObject result) {
        ComponentAnalysisCache cac = getComponentAnalysisCache(cacheType, targetHost, targetType, target);
        if (cac == null) {
            cac = new ComponentAnalysisCache();
            cac.setCacheType(cacheType);
            cac.setTargetHost(targetHost);
            cac.setTargetType(targetType);
            cac.setTarget(target);
        }
        cac.setLastOccurrence(lastOccurrence);
        if (result != null) {
            cac.setResult(result);
        }
        persist(cac);
    }

    public void clearComponentAnalysisCache() {
        final Query<ComponentAnalysisCache> query = pm.newQuery(ComponentAnalysisCache.class);
        query.deletePersistentAll();
    }
}
