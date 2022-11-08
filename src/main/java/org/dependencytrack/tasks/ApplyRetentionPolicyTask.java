package org.dependencytrack.tasks;

import static java.util.stream.Collectors.groupingBy;
import static org.apache.commons.collections4.CollectionUtils.emptyIfNull;
import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_RETENTION_POLICY;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import com.google.common.primitives.Ints;
import java.util.Comparator;
import java.util.Objects;
import java.util.Optional;
import org.dependencytrack.event.ApplyRetentionPolicyEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

/**
 * Subscriber task that applies general retention policy.
 * <p> Keeps N most recently uploaded versions of the project.
 * <p> By default, keeps all versions.
 */
public class ApplyRetentionPolicyTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ApplyRetentionPolicyTask.class);

    @Override
    public void inform(final Event event) {
        if (event instanceof ApplyRetentionPolicyEvent) {
            try (final QueryManager qm = new QueryManager()) {
                final int keepNRecent = getKeepNRecentConfigProperty(qm);
                if (keepNRecent <= 0) {
                    // keep all project versions by default
                    return;
                }

                LOGGER.info("Applying general retention policy, keeping " + keepNRecent
                        + " most recently uploaded versions of the projects");
                deleteStaleProjects(qm, keepNRecent);
            } catch (Exception e) {
                LOGGER.error("An error occurred applying general retention policy", e);
            }
        }
    }

    private void deleteStaleProjects(final QueryManager qm, final int keepNRecent) {
        final var projectNameToListOfVersions = emptyIfNull(qm.getProjects().getList(Project.class))
                .stream()
                .collect(groupingBy(Project::getName));

        projectNameToListOfVersions.values()
                .stream()
                .filter(
                        projects -> projects.stream()
                                .map(Project::getLastBomImport)
                                .allMatch(Objects::nonNull)
                )
                .forEach(
                        projectVersionsUnsorted -> projectVersionsUnsorted.stream()
                                .sorted(Comparator.comparing(Project::getLastBomImport).reversed())
                                .skip(keepNRecent)
                                .forEach(project -> qm.recursivelyDelete(project, true))
                );
    }

    private int getKeepNRecentConfigProperty(QueryManager qm) {
        final var keepNRecentConfigProperty = qm.getConfigProperty(
                GENERAL_RETENTION_POLICY.getGroupName(), GENERAL_RETENTION_POLICY.getPropertyName()
        );
        final int keepNRecent = Optional.ofNullable(keepNRecentConfigProperty.getPropertyValue())
                .map(Ints::tryParse)
                .orElse(0);
        return keepNRecent;
    }
}
