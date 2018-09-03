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
    <title>Dependency-Track - Vulnerabilities</title>
</head>
<body data-sidebar="vulnerabilities">
<jsp:include page="/WEB-INF/fragments/navbar.jsp"/>
<div id="content-container" class="container-fluid require-view-portfolio">
    <div class="content-row main">
        <div class="col-sm-12 col-md-12">
            <h3>Vulnerabilities</h3>
            <div class="widget-row">
                <div class="col-lg-3 col-md-6">
                    <div class="panel widget">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3">
                                    <i class="fa fa-shield fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge" id="statPortfolioVulnerabilities">-</div>
                                    <div>Portfolio Vulnerabilities</div>
                                </div>
                            </div>
                        </div>
                        <a href="#" class="widget-details-selector">
                            <div class="panel-footer">
                                <span class="pull-left">View Details</span>
                                <span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span>
                                <div class="clearfix"></div>
                            </div>
                        </a>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="panel widget">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3">
                                    <i class="fa fa-sitemap  fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge" id="statVulnerableProjects">-</div>
                                    <div>Projects at Risk</div>
                                </div>
                            </div>
                        </div>
                        <a href="#" class="widget-details-selector">
                            <div class="panel-footer">
                                <span class="pull-left">View Details</span>
                                <span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span>
                                <div class="clearfix"></div>
                            </div>
                        </a>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="panel widget">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3">
                                    <i class="fa fa-cubes  fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge" id="statVulnerableComponents">-</div>
                                    <div>Vulnerable Components</div>
                                </div>
                            </div>
                        </div>
                        <a href="#" class="widget-details-selector">
                            <div class="panel-footer">
                                <span class="pull-left">View Details</span>
                                <span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span>
                                <div class="clearfix"></div>
                            </div>
                        </a>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="panel widget">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3">
                                    <i class="fa fa-thermometer-half fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge" id="statInheritedRiskScore">-</div>
                                    <div>Inherited Risk Score</div>
                                </div>
                            </div>
                        </div>
                        <a href="#" class="widget-details-selector">
                            <div class="panel-footer">
                                <span class="pull-left">View Details</span>
                                <span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span>
                                <div class="clearfix"></div>
                            </div>
                        </a>
                    </div>
                </div>

            </div> <!-- /widget-row> -->

            <div id="vulnerabilitiesToolbar">
                <div class="form-inline" role="form">
                    <button id="createVulnerabilityButton" class="btn btn-default require-portfolio-management" data-toggle="modal" data-target="#modalCreateVulnerability"><span class="fa fa-plus"></span> Add Vulnerability</button>
                </div>
            </div>
            <table id="vulnerabilityTable" class="table table-hover detail-table" data-toggle="table"
                   data-url="<c:url value="/api/v1/vulnerability"/>" data-response-handler="formatVulnerabilityTable"
                   data-show-refresh="true" data-show-columns="true" data-search="true" data-detail-view="true"
                   data-query-params-type="pageSize" data-side-pagination="server" data-pagination="true"
                   data-silent-sort="false" data-page-size="10" data-page-list="[10, 25, 50, 100]"
                   data-toolbar="#vulnerabilitiesToolbar" data-click-to-select="true" data-height="100%">
                <thead>
                <tr>
                    <th data-align="left" data-class="tight" data-field="vulnerabilityhref" data-sort-name="vulnId" data-sortable="true">Name</th>
                    <th data-align="left" data-class="tight" data-field="publishedLabel" data-sort-name="published" data-sortable="true">Published</th>
                    <th data-align="left" data-class="expand" data-field="cwefield">CWE</th>
                    <th data-align="left" data-class="tight" data-field="severityLabel">Severity</th>
                </tr>
                </thead>
            </table>

        </div> <!-- /main-row> -->
    </div>

    <!-- Modals specific to components -->
    <div class="modal" id="modalCreateVulnerability" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="preview-feature-label-modal" data-toggle="tooltip" data-placement="bottom" title="Preview features provide insight into proposed new functionality in a future release. They are incomplete and are subject to change."><i class="fa fa-eye"></i> Preview Feature</span>
                    <span class="modal-title">Add Vulnerability</span>
                </div>
                <div class="panel with-nav-tabs panel-default tight panel-with-tabbed-modal-body">
                    <div class="panel-heading">
                        <ul class="nav nav-tabs">
                            <li class="active"><a href="#generalTab" data-toggle="tab">General</a></li>
                            <li><a href="#detailsTab" data-toggle="tab">Details</a></li>
                            <li><a href="#cvssv2Tab" data-toggle="tab">CVSSv2</a></li>
                            <li><a href="#cvssv3Tab" data-toggle="tab">CVSSv3</a></li>
                            <li><a href="#versionsTab" data-toggle="tab">Versions</a></li>
                        </ul>
                    </div>
                    <div class="panel-body">
                        <div class="tab-content">
                            <div class="tab-pane active" id="generalTab">
                                <div class="form-group">
                                    <label class="required" for="vulnerabilityVulnIdInput">Unique Vuln ID</label>
                                    <input type="text" name="vulnid" required="required" class="form-control required" id="vulnerabilityVulnIdInput">
                                </div>
                                <div class="form-group">
                                    <label for="vulnerabilityTitleInput">Title</label>
                                    <input type="text" name="title" class="form-control" id="vulnerabilityTitleInput">
                                </div>
                                <div class="form-group">
                                    <label for="vulnerabilitySubtitleInput">Subtitle</label>
                                    <input type="text" name="subtitle" class="form-control" id="vulnerabilitySubtitleInput">
                                </div>
                                <div class="form-group">
                                    <label for="vulnerabilityCweSelect">CWE</label>
                                    <select name="cwe" class="selectpicker form-control" title="CWE / Nothing selected..." data-live-search="true" id="vulnerabilityCweSelect">
                                        <option></option>
                                    </select>
                                </div>
                                <div class="row form-group">
                                    <label class="col-xs-1 control-label">Created</label>
                                    <div class="col-xs-4">
                                        <div class="input-group">
                                            <input type="text" class="form-control" name="date" id="vulnerabilityCreatedInput"/>
                                            <span class="input-group-addon"><span class="glyphicon glyphicon-calendar"></span></span>
                                        </div>
                                    </div>
                                </div>
                                <div class="row form-group">
                                    <label class="col-xs-1 control-label">Published</label>
                                    <div class="col-xs-4">
                                        <div class="input-group">
                                            <input type="text" class="form-control" name="date" id="vulnerabilityPublishedInput"/>
                                            <span class="input-group-addon"><span class="glyphicon glyphicon-calendar"></span></span>
                                        </div>
                                    </div>
                                </div>
                                <div class="row form-group">
                                    <label class="col-xs-1 control-label">Updated</label>
                                    <div class="col-xs-4">
                                        <div class="input-group">
                                            <input type="text" class="form-control" name="date" id="vulnerabilityUpdatedInput"/>
                                            <span class="input-group-addon"><span class="glyphicon glyphicon-calendar"></span></span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="tab-pane" id="detailsTab">
                                <div class="form-group">
                                    <label for="vulnerabilityDescriptionInput">Description</label>
                                    <textarea name="description" rows="5" class="form-control" id="vulnerabilityDescriptionInput"></textarea>
                                </div>
                                <div class="form-group">
                                    <label for="vulnerabilityRecommendationInput">Recommendation</label>
                                    <textarea name="recommendation" rows="5" class="form-control" id="vulnerabilityRecommendationInput"></textarea>
                                </div>
                                <div class="form-group">
                                    <label for="vulnerabilityReferencesInput">References</label>
                                    <textarea name="references" class="form-control" id="vulnerabilityReferencesInput"></textarea>
                                </div>
                                <div class="form-group">
                                    <label for="vulnerabilityCreditsInput">Credits</label>
                                    <input type="text" name="credits" class="form-control" id="vulnerabilityCreditsInput">
                                </div>
                            </div>
                            <div class="tab-pane" id="cvssv2Tab">
                                <div class="col-md-12">
                                    <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                        <tr>
                                            <td width="15%">&nbsp;</td>
                                            <td align="center">
                                                <span id="cvssv2BaseScorePercent" class="chart" data-percent="0">
                                                    <span id="cvssv2BaseScore" class="cvssScoreChartScore"></span>
                                                </span>
                                                <h4>Base Score</h4>
                                            </td>
                                            <td align="center">
                                                <span id="cvssv2ImpactScorePercent" class="chart" data-percent="0">
                                                    <span id="cvssv2ImpactScore" class="cvssScoreChartScore"></span>
                                                </span>
                                                <h4>Impact</h4>
                                            </td>
                                            <td align="center">
                                                <span id="cvssv2ExploitScorePercent" class="chart" data-percent="0">
                                                    <span id="cvssv2ExploitScore" class="cvssScoreChartScore"></span>
                                                </span>
                                                <h4>Exploitability</h4>
                                            </td>
                                            <td width="15%">&nbsp;</td>
                                        </tr>
                                    </table>
                                    <div class="col-md-6">
                                        <h4>Attack Vector</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Attack Vector">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2av" value="L">Local</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2av" value="A">Adjacent</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2av" value="N">Network</button>
                                            </div>
                                        </div>
                                        <h4>Access Complexity</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Access Complexity">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2ac" value="H">High</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2ac" value="M">Medium</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2ac" value="L">Low</button>
                                            </div>
                                        </div>
                                        <h4>Authentication</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Authentication">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2au" value="M">Multiple</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2au" value="S">Single</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2au" value="N">None</button>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <h4>Confidentiality Impact</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Confidentiality Impact">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2c" value="N">None</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2c" value="P">Partial</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2c" value="C">Complete</button>
                                            </div>
                                        </div>
                                        <h4>Integrity Impact</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Integrity Impact">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2i" value="N">None</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2i" value="P">Partial</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2i" value="C">Complete</button>
                                            </div>
                                        </div>
                                        <h4>Availability Impact</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Availability Impact">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2a" value="N">None</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2a" value="P">Partial</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv2-calc btn btn-default" name="v2a" value="C">Complete</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="tab-pane" id="cvssv3Tab">
                                <div class="col-md-12">
                                    <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                        <tr>
                                            <td width="15%">&nbsp;</td>
                                            <td align="center">
                                                <span id="cvssv3BaseScorePercent" class="chart" data-percent="0">
                                                    <span id="cvssv3BaseScore" class="cvssScoreChartScore"></span>
                                                </span>
                                                <h4>Base Score</h4>
                                            </td>
                                            <td align="center">
                                                <span id="cvssv3ImpactScorePercent" class="chart" data-percent="0">
                                                    <span id="cvssv3ImpactScore" class="cvssScoreChartScore"></span>
                                                </span>
                                                <h4>Impact</h4>
                                            </td>
                                            <td align="center">
                                                <span id="cvssv3ExploitScorePercent" class="chart" data-percent="0">
                                                    <span id="cvssv3ExploitScore" class="cvssScoreChartScore"></span>
                                                </span>
                                                <h4>Exploitability</h4>
                                            </td>
                                            <td width="15%">&nbsp;</td>
                                        </tr>
                                    </table>
                                    <div class="col-md-6">
                                        <h4>Attack Vector</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Attack Vector">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3av" value="N">Network</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3av" value="A">Adjacent</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3av" value="L">Local</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3av" value="P">Physical</button>
                                            </div>
                                        </div>
                                        <h4>Attack Complexity</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Attack Complexity">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3ac" value="L">Low</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3ac" value="H">High</button>
                                            </div>
                                        </div>
                                        <h4>Privileges Required</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Privileges Required">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3pr" value="N">None</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3pr" value="L">Low</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3pr" value="H">High</button>
                                            </div>
                                        </div>
                                        <h4>User Interaction</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="User Interaction">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3ui" value="N">None</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3ui" value="R">Required</button>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <h4>Scope</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Confidentiality Impact">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3s" value="U">Unchanged</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3s" value="C">Changed</button>
                                            </div>
                                        </div>
                                        <h4>Confidentiality Impact</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Confidentiality Impact">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3c" value="N">None</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3c" value="L">Low</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3c" value="H">High</button>
                                            </div>
                                        </div>
                                        <h4>Integrity Impact</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Integrity Impact">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3i" value="N">None</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3i" value="L">Low</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3i" value="H">High</button>
                                            </div>
                                        </div>
                                        <h4>Availability Impact</h4>
                                        <div class="btn-group btn-group-justified" role="group" aria-label="Availability Impact">
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3a" value="N">None</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3a" value="L">Low</button>
                                            </div>
                                            <div class="btn-group" role="group">
                                                <button type="button" class="cvssv3-calc btn btn-default" name="v3a" value="H">High</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="tab-pane" id="versionsTab">
                                <div class="form-group">
                                    <label for="vulnerabilityVulnerableVersionsInput">Vulnerable Versions</label>
                                    <textarea name="vulnerableVersions" class="form-control" id="vulnerabilityVulnerableVersionsInput"></textarea>
                                </div>
                                <div class="form-group">
                                    <label for="vulnerabilityPatchedVersionsInput">Recommendation</label>
                                    <textarea name="patchedVersions" class="form-control" id="vulnerabilityPatchedVersionsInput"></textarea>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="vulnerabilityCreateButton">Create</button>
                </div>
            </div>
        </div>
    </div>
</div>
<jsp:include page="/WEB-INF/fragments/common-modals.jsp"/>
<jsp:include page="/WEB-INF/fragments/footer.jsp"/>
<script type="text/javascript" src="<c:url value="/vulnerabilities/functions.js"/><%=VERSION_PARAM%>"></script>
</body>
</html>