package org.dependencytrack.model.vuln_vb;


import java.util.ArrayList;
import java.util.List;

public class Product implements ApiObject {
    private int id;
    private String name;
    private List<Version> versions = new ArrayList();

    public Product() {
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

    public List<Version> getVersions() {
        return this.versions;
    }

    public void setVersions(List<Version> versions) {
        this.versions = versions;
    }

    public void addVersion(Version version) {
        this.versions.add(version);
    }
}

