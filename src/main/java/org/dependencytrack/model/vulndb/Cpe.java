package org.dependencytrack.model.vulndb;

public class Cpe {
    private String cpe;
    private String type;

    public Cpe() {
    }

    public String getCpe() {
        return this.cpe;
    }

    public void setCpe(String cpe) {
        this.cpe = cpe;
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
