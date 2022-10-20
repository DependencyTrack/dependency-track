package org.dependencytrack.event;

import org.dependencytrack.model.Component;

import java.util.List;

/**
 * Defines an event used to start an analysis via Snyk REST API.
 */
public class SnykAnalysisEvent extends VulnerabilityAnalysisEvent {

    public SnykAnalysisEvent() { }

    public SnykAnalysisEvent(final Component component) {
        super(component);
    }

    public SnykAnalysisEvent(final List<Component> components) {
        super(components);
    }

}
