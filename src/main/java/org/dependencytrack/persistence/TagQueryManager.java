package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.apache.commons.collections4.CollectionUtils;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
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

    public PaginatedResult getAllTags() {
        final Query<Tag> query = pm.newQuery(Tag.class);
        query.setOrdering("COUNT(projects) desc");
        return execute(query);
    }

    public PaginatedResult getTags(List<Project> projects) {
        List<Tag> filteredTags = null;
        final Query<Tag> query = pm.newQuery(Tag.class);
        query.setOrdering("COUNT(projects) desc");
        List<Tag> allTags = query.executeList();
        for(Tag tag : allTags) {
            if(CollectionUtils.containsAny(tag.getProjects(), projects)){
                filteredTags.add(tag);
            }
        }
        return (new PaginatedResult()).objects(filteredTags).total(filteredTags.size());
    }
}
