package org.dependencytrack.model.vuln_vb;

public class Classification {
    private int id;
    private String name;
    private String longname;
    private String description;
    private String mediumtext;

    public Classification() {
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLongname() {
        return this.longname;
    }

    public void setLongname(String longname) {
        this.longname = longname;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getMediumtext() {
        return this.mediumtext;
    }

    public void setMediumtext(String mediumtext) {
        this.mediumtext = mediumtext;
    }
}
