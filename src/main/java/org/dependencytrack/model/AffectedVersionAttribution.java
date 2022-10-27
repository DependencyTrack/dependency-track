package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;
import java.util.UUID;

/**
 * Model class for tracking the attribution of vulnerable software version reporting.
 */
@PersistenceCapable
@Index(name = "AFFECTEDVERSIONATTRIBUTION_IDX", members = {"vulnerableSoftware"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AffectedVersionAttribution implements Serializable {

    private static final long serialVersionUID = -2609603709255246845L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "ATTRIBUTED_ON", allowsNull = "false")
    @NotNull
    private Date attributedOn;

    @Persistent
    @Column(name = "SOURCE", allowsNull = "false")
    private Vulnerability.Source source;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "VULNERABLE_SOFTWARE", allowsNull = "false")
    @NotNull
    private VulnerableSoftware vulnerableSoftware;

    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "AFFECTEDVERSIONATTRIBUTION_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public AffectedVersionAttribution() {}

    public AffectedVersionAttribution(Vulnerability.Source source, VulnerableSoftware vulnerableSoftware) {
        this.vulnerableSoftware = vulnerableSoftware;
        this.source = source;
        this.attributedOn = new Date();
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public VulnerableSoftware getVulnerableSoftware() {
        return vulnerableSoftware;
    }

    public void setVulnerableSoftware(VulnerableSoftware vulnerableSoftware) {
        this.vulnerableSoftware = vulnerableSoftware;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public Date getAttributedOn() {
        return attributedOn;
    }

    public void setAttributedOn(Date attributedOn) {
        this.attributedOn = attributedOn;
    }

    public Vulnerability.Source getSource() {
        return source;
    }

    public void setSource(Vulnerability.Source source) {
        this.source = source;
    }
}
