package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.apache.commons.collections4.CollectionUtils;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

final class TagQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(ProjectQueryManager.class);

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    TagQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    TagQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public PaginatedResult getTags(String policyId) {

        LOGGER.info("Retrieving tags under policy " + policyId);
        
        Policy policy = pm.getObjectById(Policy.class, policyId);
        List<Project> projects = policy.getProjects();
        final Query<Tag> query = pm.newQuery(Tag.class);

        List<Tag> tagsQueried = query.executeList();
        List<Tag> tagsToShow = new ArrayList<>(tagsQueried);

        if(projects != null && projects.size() != 0){
            for(Tag tag : tagsQueried) {
                if(!CollectionUtils.containsAny(tag.getProjects(), projects)){
                    tagsToShow.remove(tag);
                }
            }
        }
        tagsToShow.sort(Comparator.comparingInt(tag -> tag.getProjects().size()));
        Collections.reverse(tagsToShow);
        return (new PaginatedResult()).objects(tagsToShow).total(tagsToShow.size());
    }
}
