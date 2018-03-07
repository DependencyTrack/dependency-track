<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <jsp:include page="/WEB-INF/fragments/header.jsp"/>
    <title>Dependency-Track - Components</title>
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
                    <th data-align="left" data-field="vulnerabilities">Vulnerabilities</th>
                </tr>
                </thead>
            </table>

        </div> <!-- /main-row> -->
    </div>

    <!-- Modals specific to components -->
    <div class="modal" id="modalCreateComponent" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Create Component</h4>
                </div>
                <div class="panel with-nav-tabs panel-default tight panel-with-tabbed-modal-body">
                    <div class="panel-heading">
                        <ul class="nav nav-tabs">
                            <li class="active"><a href="#generalTab" data-toggle="tab">General</a></li>
                            <li><a href="#entendedTab" data-toggle="tab">Extended</a></li>
                            <li><a href="#hashesTab" data-toggle="tab">Hashes</a></li>
                        </ul>
                    </div>
                    <div class="panel-body">
                        <div class="tab-content">
                            <div class="tab-pane active" id="generalTab">
                                <div class="form-group">
                                    <label class="sr-only" for="componentNameInput">Component Name</label>
                                    <input type="text" name="name" required="true" placeholder="Name..." class="form-control" id="componentNameInput">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentVersionInput">Component Version</label>
                                    <input type="text" name="version" required="false" placeholder="Version..." class="form-control" id="componentVersionInput">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentGroupInput">Component Group</label>
                                    <input type="text" name="group" required="false" placeholder="Group..." class="form-control" id="componentGroupInput">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentDescriptionInput">Description</label>
                                    <textarea name="description" required="false" placeholder="Description..." class="form-control" id="componentDescriptionInput"></textarea>
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentLicenseSelect">License</label>
                                    <select name="license" class="selectpicker form-control" title="License / Nothing selected..." data-live-search="true" id="componentLicenseSelect">
                                        <option></option>
                                    </select>
                                </div>
                            </div>
                            <div class="tab-pane" id="entendedTab">
                                <div class="form-group">
                                    <label class="sr-only" for="componentFilenameInput">Filename</label>
                                    <input type="text" name="filename" required="true" placeholder="Filename..." class="form-control" id="componentFilenameInput">
                                </div>
                               <div class="form-group">
                                    <label class="sr-only" for="componentClassifierInput">Classifier</label>
                                    <select class="form-control" id="componentClassifierInput">
                                        <option value="APPLICATION">Application</option>
                                        <option value="FRAMEWORK">Framework</option>
                                        <option value="LIBRARY">Library</option>
                                        <option value="OPERATING_SYSTEM">Operating System</option>
                                        <option value="DEVICE">Device/Hardware</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentPurlInput">Package URL (Purl)</label>
                                    <input type="text" name="purl" required="false" placeholder="Package URL (Purl)..." class="form-control" id="componentPurlInput">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentCpeInput">CPE</label>
                                    <input type="text" name="cpe" required="false" placeholder="CPE..." class="form-control" id="componentCpeInput">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentCopyrightInput">Copyright</label>
                                    <textarea name="copyright" required="false" placeholder="Copyright..." class="form-control" id="componentCopyrightInput"></textarea>
                                </div>
                            </div>
                            <div class="tab-pane" id="hashesTab">
                                <div class="form-group">
                                    <label class="sr-only" for="componentMd5Input">MD5</label>
                                    <input type="text" name="md5" required="true" placeholder="MD5..." class="form-control" id="componentMd5Input">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentSha1Input">SHA1</label>
                                    <input type="text" name="sha1" required="true" placeholder="SHA1..." class="form-control" id="componentSha1Input">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentSha256Input">SHA 256</label>
                                    <input type="text" name="sha256" required="true" placeholder="SHA 256..." class="form-control" id="componentSha256Input">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentSha512Input">SHA 512</label>
                                    <input type="text" name="sha512" required="true" placeholder="SHA 512..." class="form-control" id="componentSha512Input">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentSha3256Input">SHA3 256</label>
                                    <input type="text" name="sha3256" required="true" placeholder="SHA3 256..." class="form-control" id="componentSha3256Input">
                                </div>
                                <div class="form-group">
                                    <label class="sr-only" for="componentSha3512Input">SHA3 512</label>
                                    <input type="text" name="sha3512" required="true" placeholder="SHA3 512..." class="form-control" id="componentSha3512Input">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="componentCreateButton">Create</button>
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