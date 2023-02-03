package org.dependencytrack.model.vulndb;

public class NvdAdditionalInfo {
    private String summary;
    private String cweId;
    private String cveId;

    public NvdAdditionalInfo() {
    }

    public String getSummary() {
        return this.summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getCweId() {
        return this.cweId;
    }

    public void setCweId(String cweId) {
        this.cweId = cweId;
    }

    public String getCveId() {
        return this.cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }
}
