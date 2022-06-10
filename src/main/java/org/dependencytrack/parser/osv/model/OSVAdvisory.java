package org.dependencytrack.parser.osv.model;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;

public class OSVAdvisory {

    private String id;

    private String details;

    private String summary;

    private String severity;

    private List<String> aliases;

    private ZonedDateTime modified;

    private ZonedDateTime published;

    private List<String> cweIds;

    private List<String> references;

    private String schema_version;

    private List<OSVVulnerability> vulnerabilities;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<String> getCweIds() {
        return cweIds;
    }

    public void addCweId(String cweId) {
        if (cweId == null) {
            cweIds = new ArrayList<>();
        }
        cweIds.add(cweId);
    }

    public void setCweIds(List<String> cweIds) {
        this.cweIds = cweIds;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<String> getAliases() {
        return aliases;
    }

    public void addAlias(String alias) {
        if (alias == null) {
            aliases = new ArrayList<>();
        }
        aliases.add(alias);
    }

    public void setAliases(List<String> aliases) {
        this.aliases = aliases;
    }

    public ZonedDateTime getModified() {
        return modified;
    }

    public void setModified(ZonedDateTime modified) {
        this.modified = modified;
    }

    public ZonedDateTime getPublished() {
        return published;
    }

    public void setPublished(ZonedDateTime published) {
        this.published = published;
    }

    public List<String> getReferences() {
        return references;
    }

    public void addReference(String reference) {
        if (this.references == null) {
            this.references = new ArrayList<>();
        }
        this.references.add(reference);
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }

    public String getSchema_version() {
        return schema_version;
    }

    public void setSchema_version(String schema_version) {
        this.schema_version = schema_version;
    }

    public List<OSVVulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void addVulnerability(OSVVulnerability vulnerability) {
        if (this.vulnerabilities == null) {
            this.vulnerabilities = new ArrayList<>();
        }
        this.vulnerabilities.add(vulnerability);
    }

    public void setVulnerabilities(List<OSVVulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }
}