package org.dependencytrack.model.vuln_vb;

import java.util.ArrayList;
import java.util.List;

public class Vendor implements ApiObject {
    private int id;
    private String name;
    private String shortName;
    private String vendorUrl;
    private List<Product> products = new ArrayList();

    public Vendor() {
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

    public String getShortName() {
        return this.shortName;
    }

    public void setShortName(String shortName) {
        this.shortName = shortName;
    }

    public String getVendorUrl() {
        return this.vendorUrl;
    }

    public void setVendorUrl(String vendorUrl) {
        this.vendorUrl = vendorUrl;
    }

    public List<Product> getProducts() {
        return this.products;
    }

    public void setProducts(List<Product> products) {
        this.products = products;
    }

    public void addProduct(Product product) {
        this.products.add(product);
    }
}
