package org.dependencytrack.resources.v1.vo;

import java.io.Serializable;

import io.swagger.annotations.ApiModelProperty;

public class IsTokenBeingProcessedResponse implements Serializable {

    private static final long serialVersionUID = -7592468766586686855L;

    @ApiModelProperty(required = true)
    private Boolean processing;

    public void setProcessing(Boolean processing) {
        this.processing = processing;
    }

    public Boolean getProcessing() {
        return this.processing;
    }
}
