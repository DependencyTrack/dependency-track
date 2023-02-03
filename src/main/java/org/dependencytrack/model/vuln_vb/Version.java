package org.dependencytrack.model.vuln_vb;

import java.util.ArrayList;
import java.util.List;

public class Version implements ApiObject {
    private int id;
    private String name;
    private boolean affected;
    private List<Cpe> cpes = new ArrayList();

    public Version() {
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

    public boolean isAffected() {
        return this.affected;
    }

    public void setAffected(boolean affected) {
        this.affected = affected;
    }

    public List<Cpe> getCpes() {
        return this.cpes;
    }

    public void setCpes(List<Cpe> cpes) {
        this.cpes = cpes;
    }

    public void addCpe(Cpe cpe) {
        this.cpes.add(cpe);
    }
}
