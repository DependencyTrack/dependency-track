<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <jsp:include page="/WEB-INF/fragments/header.jsp"/>
    <title>Dependency-Track - Component</title>
</head>
<body data-sidebar="components">
<jsp:include page="/WEB-INF/fragments/navbar.jsp"/>
<div class="container-fluid">
    <div class="widget-detail-row main" >
        <div class="col-lg-12 col-md-12">
            <div class="panel widget">
                <div class="panel-heading">
                    <div class="row">
                        <div class="col-sm-6 col-md-6 col-lg-8">
                            <div class="title-icon">
                                <i class="fa fa-cube"></i>
                            </div>
                            <div class="title-container">
                                <span class="title">
                                    <span class="name" id="componentName"></span>
                                    <span id="componentVersion"></span>
                                </span>
                                <br/><span id="componentLicense">License: Unknown</span><br/>
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
                        <li class="active"><a href="#vulnerabilitiesTab" data-toggle="tab">Vulnerabilities</a></li>
                        <li><a href="#projectsTab" data-toggle="tab">Projects</a></li>
                    </ul>
                </div>
                <div class="panel-body tight">
                    <div class="tab-content">
                        <div class="tab-pane active" id="vulnerabilitiesTab">
                            <table id="vulnerabilitiesTable" class="table table-hover detail-table" data-toggle="table"
                                   data-url="<c:url value="/api/v1/vulnerability/component/${param['uuid']}"/>"
                                   data-response-handler="formatVulnerabilitiesTable" data-detail-view="true"
                                   data-query-params-type="pageSize" data-side-pagination="server" data-pagination="true"
                                   data-page-size="10" data-page-list="[10, 25, 50, 100]"
                                   data-click-to-select="true" data-height="100%">
                                <thead>
                                <tr>
                                    <th data-align="left" data-class="tight" data-field="vulnerabilityhref">Name</th>
                                    <th data-align="left" data-class="tight" data-field="publishedLabel">Published</th>
                                    <th data-align="left" data-class="expand" data-field="cwefield">CWE</th>
                                    <th data-align="left" data-class="tight" data-field="severityLabel">Severity</th>
                                </tr>
                                </thead>
                            </table>
                        </div>
                        <div class="tab-pane" id="projectsTab">
                            <table id="projectsTable" class="table table-hover detail-table" data-toggle="table"
                                   data-url="<c:url value="/api/v1/dependency/component/${param['uuid']}"/>"
                                   data-response-handler="formatProjectsTable" data-detail-view="true"
                                   data-query-params-type="pageSize" data-side-pagination="server" data-pagination="true"
                                   data-page-size="10" data-page-list="[10, 25, 50, 100]"
                                   data-click-to-select="true" data-height="100%">
                                <thead>
                                <tr>
                                    <th data-align="left" data-field="project.projecthref">Name</th>
                                    <th data-align="left" data-field="project.version">Version</th>
                                </tr>
                                </thead>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modals specific to a component -->
    <div class="modal" id="modalDetails" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="modal-title">Component Details</span>
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
                                    <label class="required" for="componentNameInput">Component Name</label>
                                    <input type="text" name="name" required="required" class="form-control required" id="componentNameInput">
                                </div>
                                <div class="form-group">
                                    <label class="required" for="componentVersionInput">Version</label>
                                    <input type="text" name="version" required="required" class="form-control required" id="componentVersionInput">
                                </div>
                                <div class="form-group">
                                    <label for="componentGroupInput">Group / Vendor</label>
                                    <input type="text" name="group" class="form-control" id="componentGroupInput">
                                </div>
                                <div class="form-group">
                                    <label for="componentDescriptionInput">Description</label>
                                    <textarea name="description" class="form-control" id="componentDescriptionInput"></textarea>
                                </div>
                                <div class="form-group">
                                    <label for="componentLicenseSelect">License</label>
                                    <select name="license" class="selectpicker form-control" title="License / Nothing selected..." data-live-search="true" id="componentLicenseSelect">
                                        <option></option>
                                    </select>
                                </div>
                            </div>
                            <div class="tab-pane" id="entendedTab">
                                <div class="form-group">
                                    <label for="componentFilenameInput">Filename</label>
                                    <input type="text" name="filename" class="form-control" id="componentFilenameInput">
                                </div>
                                <div class="form-group">
                                    <label for="componentClassifierInput">Classifier</label>
                                    <select class="form-control" id="componentClassifierInput">
                                        <option value="" disabled="disabled" selected="selected">Select...</option>
                                        <option value="APPLICATION">Application</option>
                                        <option value="FRAMEWORK">Framework</option>
                                        <option value="LIBRARY">Library</option>
                                        <option value="OPERATING_SYSTEM">Operating System</option>
                                        <option value="DEVICE">Device/Hardware</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="componentPurlInput">Package URL (Purl)</label>
                                    <input type="text" name="purl" class="form-control" id="componentPurlInput">
                                </div>
                                <div class="form-group">
                                    <label for="componentCpeInput">CPE</label>
                                    <input type="text" name="cpe" class="form-control" id="componentCpeInput">
                                </div>
                                <div class="form-group">
                                    <label for="componentCopyrightInput">Copyright</label>
                                    <textarea name="copyright" class="form-control" id="componentCopyrightInput"></textarea>
                                </div>
                            </div>
                            <div class="tab-pane" id="hashesTab">
                                <div class="form-group">
                                    <label for="componentMd5Input">MD5</label>
                                    <input type="text" name="md5" pattern="[A-Fa-f0-9]{32}" class="hash-input form-control" id="componentMd5Input">
                                </div>
                                <div class="form-group">
                                    <label for="componentSha1Input">SHA1</label>
                                    <input type="text" name="sha1" pattern="[A-Fa-f0-9]{40}" class="hash-input form-control" id="componentSha1Input">
                                </div>
                                <div class="form-group">
                                    <label for="componentSha256Input">SHA 256</label>
                                    <input type="text" name="sha256" pattern="[A-Fa-f0-9]{64}" class="hash-input form-control" id="componentSha256Input">
                                </div>
                                <div class="form-group">
                                    <label for="componentSha512Input">SHA 512</label>
                                    <input type="text" name="sha512" pattern="[A-Fa-f0-9]{128}" class="hash-input form-control" id="componentSha512Input">
                                </div>
                                <div class="form-group">
                                    <label for="componentSha3256Input">SHA3 256</label>
                                    <input type="text" name="sha3256" pattern="[A-Fa-f0-9]{64}" class="hash-input form-control" id="componentSha3256Input">
                                </div>
                                <div class="form-group">
                                    <label for="componentSha3512Input">SHA3 512</label>
                                    <input type="text" name="sha3512" pattern="[A-Fa-f0-9]{128}" class="hash-input form-control" id="componentSha3512Input">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-danger" data-dismiss="modal" id="deleteComponentButton">Delete</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="updateComponentButton">Update</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <jsp:include page="/WEB-INF/fragments/common-modals.jsp"/>
</div>
<jsp:include page="/WEB-INF/fragments/footer.jsp"/>
<script type="text/javascript" src="<c:url value="/component/functions.js"/>"></script>
</body>
</html>