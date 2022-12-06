package org.dependencytrack.resources.v1.vo;

import java.io.Serializable;
import java.util.UUID;

import io.swagger.annotations.ApiModelProperty;

public class BomUploadResponse implements Serializable {

    private static final long serialVersionUID = -7592436786586686865L;

    @ApiModelProperty(required = true, value = "Token used to check task progress")
    private UUID token;

    public void setToken(UUID token) {
        this.token = token;
    }

    public UUID getToken() {
        return this.token;
    }
}
