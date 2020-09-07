package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.Pattern;

/**
 * Defines a custom request object used when adding a new MappedOidcGroup.
 *
 * @since 4.0.0
 */
public class MappedOidcGroupRequest {

    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The team must be a valid 36 character UUID")
    private String team;

    @Pattern(regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", message = "The group must be a valid 36 character UUID")
    private String group;

    @JsonCreator
    public MappedOidcGroupRequest(@JsonProperty(value = "team", required = true) final String team,
                                  @JsonProperty(value = "group", required = true) final String group) {
        this.team = team;
        this.group = group;
    }

    public String getTeam() {
        return team;
    }

    public void setTeam(String team) {
        this.team = team;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

}
