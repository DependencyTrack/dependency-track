package org.dependencytrack.model.VulnDb;

public class ExternalReference {
    private String type;
    private String value;

    public ExternalReference() {
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getValue() {
        return this.value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
