<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <jsp:include page="/WEB-INF/fragments/header.jsp"/>
    <title>OWASP Dependency-Track - Components</title>
</head>
<body data-sidebar="components">
<jsp:include page="/WEB-INF/fragments/navbar.jsp"/>
<div class="container-fluid">
    <div class="content-row main">
        <div class="col-sm-12 col-md-12">
            <h3>Components</h3>
            <div class="widget-row">
                <div class="col-lg-3 col-md-6">
                    <div class="panel widget">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3">
                                    <i class="fa fa-shield fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge">206</div>
                                    <div>Portfolio Vulnerabilities</div>
                                </div>
                            </div>
                        </div>
                        <a href="#">
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
                                    <i class="fa fa-thermometer-half  fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge">15</div>
                                    <div>Projects at Risk</div>
                                </div>
                            </div>
                        </div>
                        <a href="#">
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
                                    <i class="fa fa-balance-scale fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge">26</div>
                                    <div>Policy Violations</div>
                                </div>
                            </div>
                        </div>
                        <a href="#">
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
                                    <i class="fa fa-bell fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge">5</div>
                                    <div>Recent Alerts</div>
                                </div>
                            </div>
                        </div>
                        <a href="#">
                            <div class="panel-footer">
                                <span class="pull-left">View Details</span>
                                <span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span>
                                <div class="clearfix"></div>
                            </div>
                        </a>
                    </div>
                </div>

            </div> <!-- /widget-row> -->

            <div id="componentsToolbar">
                <div class="form-inline" role="form">
                    <button id="createComponentButton" class="btn btn-default" data-toggle="modal" data-target="#modalCreateComponent"><span class="fa fa-plus"></span> Create Component</button>
                </div>
            </div>
            <table id="componentsTable" class="table table-hover detail-table" data-toggle="table"
                   data-url="<c:url value="/api/v1/component"/>" data-response-handler="formatComponentsTable"
                   data-show-refresh="true" data-show-columns="true" data-search="true" data-detail-view="true"
                   data-query-params-type="pageSize" data-side-pagination="server" data-pagination="true"
                   data-page-size="10" data-page-list="[10, 25, 50, 100]"
                   data-toolbar="#componentsToolbar" data-click-to-select="true" data-height="100%">
                <thead>
                <tr>
                    <th data-align="left" data-field="componenthref">Name</th>
                    <th data-align="left" data-field="version">Version</th>
                    <th data-align="left" data-field="group">Group</th>
                    <th data-align="left" data-field="license">License</th>
                    <th data-align="left" data-field="vulns">Vulnerabilities</th>
                    <th data-align="left" data-field="irs">Security Risk</th>
                </tr>
                </thead>
            </table>

        </div> <!-- /main-row> -->
    </div>

    <!-- Modals specific to components -->
    <div class="modal" id="modalCreateComponent" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Create Component</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="sr-only" for="createComponentNameInput">Component Name</label>
                        <input type="text" name="name" required="true" placeholder="Name..." class="form-control" id="createComponentNameInput">
                    </div>
                    <div class="form-group">
                        <label class="sr-only" for="createComponentVersionInput">Component Version</label>
                        <input type="text" name="version" required="false" placeholder="Version..." class="form-control" id="createComponentVersionInput">
                    </div>
                    <div class="form-group">
                        <label class="sr-only" for="createComponentGroupInput">Component Group</label>
                        <input type="text" name="group" required="false" placeholder="Group..." class="form-control" id="createComponentGroupInput">
                    </div>
                    <div class="form-group">
                        <label class="sr-only" for="createComponentDescriptionInput">Group</label>
                        <textarea name="description" required="false" placeholder="Description..." class="form-control" id="createComponentDescriptionInput"></textarea>
                    </div>
                    <div class="form-group">
                        <label class="sr-only" for="createComponentLicenseSelect">License</label>
                        <select name="license" class="selectpicker form-control" title="License / Nothing selected..." data-live-search="true" id="createComponentLicenseSelect">
                            <option></option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="createComponentCreateButton">Create</button>
                </div>
            </div>
        </div>
    </div>

    <jsp:include page="/WEB-INF/fragments/common-modals.jsp"/>
</div>
<jsp:include page="/WEB-INF/fragments/footer.jsp"/>
<script type="text/javascript" src="<c:url value="/components/functions.js"/>"></script>
</body>
</html>