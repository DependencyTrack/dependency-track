package org.dependencytrack.model.vuln_vb;

import java.util.ArrayList;
import java.util.List;

public class Results<T> {
    private int page;
    private int total;
    private List<T> results = new ArrayList();
    private String rawResults;
    private String errorCondition;

    public Results() {
    }

    public int getPage() {
        return this.page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public int getTotal() {
        return this.total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public List<T> getResults() {
        return this.results;
    }

    public void setResults(List objects) {
        this.results = objects;
    }

    public void add(T object) {
        this.results.add(object);
    }

    public String getRawResults() {
        return this.rawResults;
    }

    public void setRawResults(String rawResults) {
        this.rawResults = rawResults;
    }

    public boolean isSuccessful() {
        return this.errorCondition == null;
    }

    public String getErrorCondition() {
        return this.errorCondition;
    }

    public void setErrorCondition(String errorCondition) {
        this.errorCondition = errorCondition;
    }
}
