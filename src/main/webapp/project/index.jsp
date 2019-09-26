<%@page import="alpine.Config" %>
<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<%!
    private static final String BUILD_ID = Config.getInstance().getApplicationBuildUuid();
    private static final String VERSION_PARAM = "?v=" + BUILD_ID;
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <jsp:include page="/WEB-INF/fragments/header.jsp"/>
    <title>Dependency-Track - Project Details</title>
</head>
<body data-sidebar="projects">
<jsp:include page="/WEB-INF/fragments/navbar.jsp"/>
<div id="content-container" class="container-fluid require-view-portfolio">
    <div class="widget-detail-row main">
        <div class="col-lg-12 col-md-12">
            <div class="panel widget">
                <div class="panel-heading">
                    <div class="row">
                        <div class="col-sm-6 col-md-6 col-lg-8">
                            <div class="title-icon">
                                <i class="fa fa-sitemap"></i>
                            </div>
                            <div class="title-container">
                                <span class="title">
                                    <span class="name" id="projectTitle"></span>
                                    <span id="projectVersion"></span>
                                </span>
                                <div class="form-inline" role="form">
                                    <div class="form-group">
                                        <select name="version" class="selectpicker form-control" title="Version" data-live-search="true" data-width="200px" id="projectVersionSelect"></select>
                                    </div>
                                </div>
                                <span id="tags"></span>
                            </div>
                        </div>
                        <div class="col-sm-3 col-md-3 col-lg-2">
                            <table style="width:100%; height:85px;">
                                <tr>
                                    <td style="vertical-align: middle;">
                                        <table>
                                            <tr>
                                                <td width="100%"></td>
                                                <td nowrap><span class="severity-critical fa fa-circle-o"></span>&nbsp;Critical Severity:&nbsp;</td>
                                                <td nowrap><span id="metricCritical"></span></td>
                                            </tr>
                                            <tr>
                                                <td></td>
                                                <td nowrap><span class="severity-high fa fa-circle-o"></span>&nbsp;High Severity:&nbsp;</td>
                                                <td nowrap><span id="metricHigh"></span></td>
                                            </tr>
                                            <tr>
                                                <td></td>
                                                <td nowrap><span class="severity-medium fa fa-circle-o"></span>&nbsp;Medium Severity:&nbsp;</td>
                                                <td nowrap><span id="metricMedium"></span></td>
                                            </tr>
                                            <tr>
                                                <td></td>
                                                <td nowrap><span class="severity-low fa fa-circle-o"></span>&nbsp;Low Severity:&nbsp;</td>
                                                <td nowrap><span id="metricLow"></span></td>
                                            </tr>
                                            <tr>
                                                <td></td>
                                                <td nowrap><span class="severity-unassigned fa fa-circle-o"></span>&nbsp;Unassigned Severity:&nbsp;</td>
                                                <td nowrap><span id="metricUnassigned"></span></td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </div>
                        <div class="col-sm-3 col-md-3 col-lg-2 text-right">
                            <div class="huge"><span id="metricIrs"></span></div>
                            <div>Inherited Risk Score</div>
                        </div>

                    </div>
                </div>
                <a href="#" class="widget-details-selector" data-toggle="modal" data-target="#modalDetails">
                    <div class="panel-footer">
                        <span class="pull-left">View Details</span>
                        <span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span>
                        <div class="clearfix"></div>
                    </div>
                </a>
            </div>
        </div>
    </div>
    <div class="content-row main">
        <div class="col-sm-12 col-md-12">
            <div class="panel with-nav-tabs panel-default tight">
                <div class="panel-heading">
                    <ul class="nav nav-tabs">
                        <li class="active"><a href="#overviewTab" data-toggle="tab"><i class="fa fa-line-chart"></i> Overview</a></li>
                        <li><a href="#dependenciesTab" data-toggle="tab"><i class="fa fa-cubes"></i> Dependencies</a></li>
                        <li class="require-vulnerability-analysis"><a href="#auditTab" data-toggle="tab"><i class="fa fa-tasks"></i> Audit</a></li>
                    </ul>
                </div>
                <div class="panel-body tight">
                    <div class="tab-content">
                        <div class="tab-pane active" id="overviewTab">
                            <!-- Left Column -->
                            <div class="col-lg-8">
                                <div id="projectchart" style="height:200px"></div>
                                <div id="auditchart" style="height:200px"></div>
                                <div id="componentchart" style="height:200px"></div>
                            </div>
                            <!-- Right Column -->
                            <div class="col-lg-4">
                                <!-- Statistics -->
                                <div class="widget-row widget-overview-first">
                                    <div class="col-sm-12">
                                        <div class="panel widget">
                                            <div class="panel-heading">
                                                <table width="100%" class="table widget-table">
                                                    <tr>
                                                        <td>Components</td>
                                                        <td><span id="statTotalComponents"></span></td>
                                                    </tr>
                                                    <tr>
                                                        <td>Vulnerable Components</td>
                                                        <td><span id="statVulnerableComponents"></span></td>
                                                    </tr>
                                                    <tr>
                                                        <td>Vulnerabilities</td>
                                                        <td><span id="statVulnerabilities"></span></td>
                                                    </tr>
                                                    <tr>
                                                        <td>Findings Audited</td>
                                                        <td><span id="statFindingsAudited"></span></td>
                                                    </tr>
                                                    <tr>
                                                        <td>Findings Audited %</td>
                                                        <td><span id="statFindingsAuditedPercent"></span></td>
                                                    </tr>
                                                    <tr>
                                                        <td>Suppressed</td>
                                                        <td><span id="statSuppressed"></span></td>
                                                    </tr>
                                                    <tr>
                                                        <td>Last Measurement</td>
                                                        <td><span id="statLastMeasurement"></span>&nbsp;&nbsp;<span id="refresh" class="refresh-metric require-portfolio-management"><i class="fa fa-refresh" aria-hidden="true"></i></span></td>
                                                    </tr>
                                                </table>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="tab-pane" id="dependenciesTab">
                            <div id="componentsToolbar">
                                <div class="form-inline" role="form">
                                    <button id="addDependencyButton" class="btn btn-default require-portfolio-management" data-toggle="modal" data-target="#modalAddDependency"><span class="fa fa-plus"></span> Add Dependency</button>
                                    <button id="removeDependencyButton" class="btn btn-default require-portfolio-management"><span class="fa fa-minus"></span> Remove Dependency</button>
                                    <button id="uploadBomDisplayModalButton" class="btn btn-default require-portfolio-management" data-toggle="modal" data-target="#modalUploadBom"><span class="fa fa-upload"></span> Upload BOM</button>
                                </div>
                            </div>
                            <table id="dependenciesTable" class="table table-hover detail-table" data-toggle="table"
                                   data-url="<c:url value="/api/v1/dependency/project/${e:forUriComponent(param.uuid)}"/>" data-response-handler="formatDependenciesTable"
                                   data-show-refresh="true" data-show-columns="true" data-search="true" data-detail-view="true"
                                   data-query-params-type="pageSize" data-side-pagination="server" data-pagination="true"
                                   data-silent-sort="false" data-page-size="10" data-page-list="[10, 25, 50, 100]"
                                   data-toolbar="#componentsToolbar" data-click-to-select="true" data-height="100%">
                                <thead>
                                <tr>
                                    <th data-align="center" data-field="state" data-checkbox="true"></th>
                                    <th data-align="left" data-field="componenthref" data-sort-name="component.name" data-sortable="true">Component</th>
                                    <th data-align="left" data-field="component.version">Version</th>
                                    <th data-align="left" data-field="latestVersion" data-visible="false">Latest Version</th>
                                    <th data-align="left" data-field="component.group" data-sort-name="component.group" data-sortable="true">Group</th>
                                    <th data-align="left" data-field="component.license">License</th>
                                    <th data-align="left" data-field="component.lastInheritedRiskScore" data-sortable="true" class="tight">Risk Score</th>
                                    <th data-align="left" data-field="vulnerabilities">Vulnerabilities</th>
                                </tr>
                                </thead>
                            </table>
                        </div>
                        <div class="tab-pane require-vulnerability-analysis" id="auditTab">
                            <table id="findingsTable" class="table table-hover detail-table" data-toggle="table"
                                   data-response-handler="formatFindingsTable"
                                   data-show-refresh="true" data-show-columns="true" data-search="true"
                                   data-detail-view="true" data-detail-formatter="findingDetailFormatter"
                                   data-query-params-type="pageSize" data-side-pagination="client" data-pagination="true"
                                   data-silent-sort="false" data-page-size="10" data-page-list="[10, 25, 50, 100]"
                                   data-click-to-select="true" data-height="100%">
                                <thead>
                                <tr>
                                    <th data-align="left" data-field="component.name" data-sortable="true">Component</th>
                                    <th data-align="left" data-field="component.version" data-sortable="true">Version</th>
                                    <th data-align="left" data-field="component.group" data-sortable="true">Group</th>
                                    <th data-align="left" data-field="vulnerability.href" data-sort-name="vulnerability.vulnId" data-sortable="true">Vulnerability</th>
                                    <th data-align="left" data-class="expand-20" data-field="vulnerability.cwefield" data-sortable="true">CWE</th>
                                    <th data-align="left" data-field="vulnerability.severityLabel" data-sort-name="vulnerability.severityRank" data-sortable="true">Severity</th>
                                    <th data-align="left" data-field="analysis.state" data-sortable="true">Analysis</th>
                                    <th data-align="center" data-field="analysis.isSuppressedLabel" data-sortable="true" data-class="tight">Suppressed</th>
                                </tr>
                                </thead>
                            </table>
                        </div>
                        <!-- end of tabs -->


                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modals specific to a project -->
    <div class="modal" id="modalAddDependency" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="modal-title">Add Dependency</span>
                </div>
                <div class="panel with-nav-tabs panel-default tight panel-with-tabbed-modal-body">
                    <div class="panel-heading">
                        <ul class="nav nav-tabs">
                            <li class="active"><a href="#fromExistingTab" data-toggle="tab">From Existing Component</a></li>
                            <li><a href="#fromNewTab" data-toggle="tab">From New Component</a></li>
                        </ul>
                    </div>
                    <div class="panel-body tight">
                        <div class="tab-content">
                            <div class="tab-pane active" id="fromExistingTab">
                                <div class="modal-body">
                                    <table id="componentsTable" class="table table-hover" data-toggle="table"
                                           data-url="<c:url value="/api/v1/component"/>" data-response-handler="formatComponentsTable"
                                           data-search="true" data-click-to-select="true" data-page-size="5"
                                           data-query-params-type="pageSize" data-side-pagination="server" data-pagination="true">
                                        <thead>
                                        <tr>
                                            <th data-align="center" data-field="state" data-checkbox="true"></th>
                                            <th data-align="left" data-field="name">Name</th>
                                            <th data-align="left" data-field="version">Version</th>
                                            <th data-align="left" data-field="group">Group</th>
                                        </tr>
                                        </thead>
                                    </table>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="addDependencyFromExistingButton">Add Dependency</button>
                                </div>
                            </div>
                            <div class="tab-pane" id="fromNewTab">
                                <div class="modal-body">
                                    <div class="form-group">
                                        <label class="required" for="createComponentNameInput">Component Name</label>
                                        <input type="text" name="name" required="required" class="form-control required" id="createComponentNameInput">
                                    </div>
                                    <div class="form-group">
                                        <label class="required" for="createComponentVersionInput">Version</label>
                                        <input type="text" name="version" required="required" class="form-control required" id="createComponentVersionInput">
                                    </div>
                                    <div class="form-group">
                                        <label for="createComponentGroupInput">Group / Vendor</label>
                                        <input type="text" name="group" class="form-control" id="createComponentGroupInput">
                                    </div>
                                    <div class="form-group">
                                        <label for="createComponentDescriptionInput">Description</label>
                                        <textarea name="description" class="form-control" id="createComponentDescriptionInput"></textarea>
                                    </div>
                                    <div class="form-group">
                                        <label for="createComponentLicenseSelect">License</label>
                                        <select name="license" class="selectpicker form-control" title="License / Nothing selected..." data-live-search="true" id="createComponentLicenseSelect">
                                            <option></option>
                                        </select>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="addDependencyFromNewButton">Add Dependency</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="modalDetails" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="modal-title">Project Details</span>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="required" for="projectNameInput">Project Name</label>
                        <input type="text" name="name" required="required" class="form-control required require-portfolio-management" disabled="disabled" id="projectNameInput">
                    </div>
                    <div class="form-group">
                        <label for="projectVersionInput">Version</label>
                        <input type="text" name="version" class="form-control require-portfolio-management" disabled="disabled" id="projectVersionInput">
                    </div>
                    <div class="form-group">
                        <label for="projectDescriptionInput">Description</label>
                        <textarea name="description" class="form-control require-portfolio-management" disabled="disabled" id="projectDescriptionInput"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="projectTagsInput">Tags</label>
                        <input type="text" name="tags" placeholder="Comma separated" class="form-control require-portfolio-management" disabled="disabled" data-role="tagsinput" id="projectTagsInput">
                    </div>
                    <div class="form-group">
                        <input type="checkbox" name="active" class="require-portfolio-management" id="projectActiveInput">
                        <label for="projectActiveInput"> Active</label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-danger require-portfolio-management" data-dismiss="modal" id="deleteProjectButton">Delete</button>
                    <button type="button" class="btn btn-default require-portfolio-management" data-dismiss="modal" data-toggle="modal" data-target="#modalProjectProperties">Properties</button>
                    <button type="button" class="btn btn-primary require-portfolio-management" data-dismiss="modal" data-toggle="modal" data-target="#modalCloneProject">Add Version</button>
                    <button type="button" class="btn btn-primary require-portfolio-management" data-dismiss="modal" id="updateProjectButton">Update</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="modalCloneProject" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="modal-title">Add Version</span>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="projectVersionInput">Version</label>
                        <input type="text" name="version" class="form-control require-portfolio-management" disabled="disabled" id="cloneProjectVersionInput">
                    </div>
                    <div class="checkbox">
                        <label><input type="checkbox" checked="checked" id="cloneProjectIncludeTagsInput"> Include tags</label>
                    </div>
                    <div class="checkbox">
                        <label><input type="checkbox" checked="checked" id="cloneProjectIncludePropertiesInput"> Include properties</label>
                    </div>
                    <div class="checkbox">
                        <label><input type="checkbox" checked="checked" id="cloneProjectIncludeDependenciesInput"> Include dependencies</label>
                    </div>
                    <div class="checkbox">
                        <label><input type="checkbox" checked="checked" id="cloneProjectIncludeAuditHistoryInput"> Include audit history</label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-primary require-portfolio-management" data-dismiss="modal" id="cloneProjectButton">Create</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="modalUploadBom" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="modal-title">Upload BOM</span>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <div class="input-group input-file">
			                <span class="input-group-btn">
        		                <button class="btn btn-default btn-choose" type="button">Choose</button>
    		                </span>
                            <input type="text" class="form-control" placeholder="Choose a CycloneDX or SPDX BOM..."/>
                            <span class="input-group-btn">
       			                <button class="btn btn-warning btn-reset" type="button">Reset</button>
    		                </span>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="uploadBomButton">Upload</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="modalProjectProperties" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="modal-title">Project Properties</span>
                </div>
                <div class="modal-body">
                    <table id="projectPropertiesTable" class="table table-hover detail-table" data-toggle="table"
                           data-response-handler="formatProjectPropertiesTable"
                           data-show-refresh="true" data-show-columns="true" data-search="true" data-detail-view="true"
                           data-query-params-type="pageSize" data-side-pagination="client" data-pagination="true"
                           data-silent-sort="false" data-page-size="5" data-height="100%">
                        <thead>
                        <tr>
                            <th data-align="center" data-field="state" data-checkbox="true"></th>
                            <th data-field="groupName">Group</th>
                            <th data-field="propertyName">Name</th>
                            <th data-field="propertyValue" data-editable="true">Value</th>
                            <th data-field="propertyType">Type</th>
                            <th data-field="description" data-visible="false">Description</th>
                        </tr>
                        </thead>
                    </table>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-danger require-portfolio-management" id="deleteProjectPropertyButton">Delete</button>
                    <button type="button" class="btn btn-primary require-portfolio-management" data-toggle="modal" data-target="#modalCreateProjectProperty">Create Property</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal" id="modalCreateProjectProperty" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="modal-title">Create Project Property</span>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="required" for="createProjectPropertyGroupNameInput">Group Name</label>
                        <input type="text" required="required" class="form-control required" id="createProjectPropertyGroupNameInput" maxlength="255">
                    </div>
                    <div class="form-group">
                        <label class="required" for="createProjectPropertyNameInput">Property Name</label>
                        <input type="text" required="required" class="form-control required" id="createProjectPropertyNameInput" maxlength="255">
                    </div>
                    <div class="form-group">
                        <label class="required" for="createProjectPropertyValueInput">Property Value</label>
                        <input type="text" required="required" class="form-control required" id="createProjectPropertyValueInput" maxlength="255">
                    </div>
                    <div class="form-group">
                        <label class="required" for="createProjectPropertyTypeInput">Property Type</label>
                        <select required="required" class="form-control required" id="createProjectPropertyTypeInput">
                            <option value="BOOLEAN">BOOLEAN</option>
                            <option value="INTEGER">INTEGER</option>
                            <option value="NUMBER">NUMBER</option>
                            <option value="STRING">STRING</option>
                            <option value="ENCRYPTEDSTRING">ENCRYPTEDSTRING</option>
                            <option value="TIMESTAMP">TIMESTAMP</option>
                            <option value="URL">URL</option>
                            <option value="UUID">UUID</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="createProjectPropertyDescriptionInput">Description</label>
                        <input type="text" class="form-control" id="createProjectPropertyDescriptionInput" maxlength="255">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="createProjectPropertyCreateButton">Create</button>
                </div>
            </div>
        </div>
    </div>

</div>
<jsp:include page="/WEB-INF/fragments/common-modals.jsp"/>
<jsp:include page="/WEB-INF/fragments/footer.jsp"/>
<script type="text/javascript" src="<c:url value="/project/functions.js"/><%=VERSION_PARAM%>"></script>
</body>
</html>
