<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <jsp:include page="/WEB-INF/fragments/header.jsp"/>
    <title>Dependency-Track - Projects</title>
</head>
<body data-sidebar="projects">
<jsp:include page="/WEB-INF/fragments/navbar.jsp"/>
<div class="container-fluid">
    <div class="content-row main">
        <div class="col-sm-12 col-md-12">
            <h3>Projects</h3>
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

            <div id="projectsToolbar">
                <div class="form-inline" role="form">
                    <button id="createProjectButton" class="btn btn-default" data-toggle="modal" data-target="#modalCreateProject"><span class="fa fa-plus"></span> Create Project</button>
                </div>
            </div>
                <table id="projectsTable" class="table table-hover detail-table" data-toggle="table"
                       data-url="<c:url value="/api/v1/project"/>" data-response-handler="formatProjectsTable"
                       data-show-refresh="true" data-show-columns="true" data-search="true" data-detail-view="true"
                       data-query-params-type="pageSize" data-side-pagination="server" data-pagination="true"
                       data-page-size="10" data-page-list="[10, 25, 50, 100]"
                       data-toolbar="#projectsToolbar" data-click-to-select="true" data-height="100%">
                <thead>
                <tr>
                    <th data-align="left" data-field="projecthref">Project Name</th>
                    <th data-align="left" data-field="lastscan">Last Scanned</th>
                    <th data-align="left" data-field="bomupdated">BOM Updated</th>
                    <th data-align="left" data-field="subprojects">Sub Projects</th>
                    <th data-align="left" data-field="versions">Versions</th>
                    <th data-align="left" data-field="vulnerabilities">Vulnerabilities</th>
                </tr>
                </thead>
            </table>

        </div> <!-- /main-row> -->
    </div>

    <!-- Modals specific to projects -->
    <div class="modal" id="modalCreateProject" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Create Project</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="sr-only" for="createProjectNameInput">Team Name</label>
                        <input type="text" name="name" required="true" placeholder="Project Name..." class="form-control" id="createProjectNameInput">
                    </div>
                    <div class="form-group">
                        <label class="sr-only" for="createProjectVersionInput">Team Name</label>
                        <input type="text" name="version" required="true" placeholder="Version..." class="form-control" id="createProjectVersionInput">
                    </div>
                    <div class="form-group">
                        <label class="sr-only" for="createProjectDescriptionInput">Description</label>
                        <textarea name="description" required="true" placeholder="Description" class="form-control" id="createProjectDescriptionInput"></textarea>
                    </div>
                    <div class="form-group">
                        <label class="sr-only" for="createProjectTagsInput">Tags</label>
                        <input type="text" name="version" placeholder="Tags, comma separated" class="form-control" data-role="tagsinput" id="createProjectTagsInput">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="createProjectCreateButton">Create</button>
                </div>
            </div>
        </div>
    </div>

    <jsp:include page="/WEB-INF/fragments/common-modals.jsp"/>
</div>
<jsp:include page="/WEB-INF/fragments/footer.jsp"/>
<script type="text/javascript" src="<c:url value="/projects/functions.js"/>"></script>
</body>
</html>