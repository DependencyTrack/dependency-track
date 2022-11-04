package org.dependencytrack.model;

import java.util.ArrayList;
import java.util.List;

public class NotificationAlias {

    private Vulnerability.Source source;
    private String vulnId;
    private List<Vulnerability.Source> reportedBy;

    public NotificationAlias(Vulnerability.Source source, String vulnId, List<Vulnerability.Source> reportedBy) {
        this.setSource(source);
        this.setVulnId(vulnId);
        this.setReportedBy(reportedBy);
    }

    public NotificationAlias() {
    }

    public Vulnerability.Source getSource() {
        return source;
    }

    public void setSource(Vulnerability.Source source) {
        this.source = source;
    }

    public String getVulnId() {
        return vulnId;
    }

    public void setVulnId(String vulnId) {
        this.vulnId = vulnId;
    }

    public List<Vulnerability.Source> getReportedBy() {
        return reportedBy;
    }

    public void setReportedBy(List<Vulnerability.Source> reportedBy) {
        this.reportedBy = reportedBy;
    }

    public void addReportedBy(Vulnerability.Source reportedBy) {
        if (reportedBy == null) {
            return;
        }
        if (this.reportedBy == null) {
            this.reportedBy = new ArrayList<>();
        }
        this.reportedBy.add(reportedBy);
    }
}
