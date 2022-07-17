package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;

import javax.jdo.PersistenceManager;
import java.util.*;

public class TagQueryManager extends QueryManager implements IQueryManager {

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

    public PaginatedResult getTags(String policyUuid) {

        LOGGER.debug("Retrieving tags under policy " + policyUuid);

        Policy policy = getObjectByUuid(Policy.class, policyUuid);
        List<Project> projects = policy.getProjects();

        List<Tag> tagsToShow;

        if (projects != null && !projects.isEmpty()) {
            Set<Tag> filteredTags = new HashSet<>();
            for (Project project : projects) {
                filteredTags.addAll(project.getTags());
            }
            tagsToShow = new ArrayList<>(filteredTags);
        } else {
            List<Tag> tagsQueried = pm.newQuery(Tag.class).executeList();
            tagsToShow = new ArrayList<>(tagsQueried);
        }
        tagsToShow.sort(Comparator.comparingInt(tag -> tag.getProjects().size()));
        Collections.reverse(tagsToShow);
        return (new PaginatedResult()).objects(tagsToShow).total(tagsToShow.size());
    }
}
