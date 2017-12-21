<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <jsp:include page="/WEB-INF/fragments/header.jsp"/>
    <title>Dependency-Track</title>
</head>
<body data-sidebar="dashboard">
<jsp:include page="/WEB-INF/fragments/navbar.jsp"/>
<div class="container-fluid">
    <div class="content-row main">
        <div class="col-sm-12 col-md-12">
            <h3>Dashboard</h3>
            <div class="widget-row">
                <!-- Left Column -->
                <div class="col-lg-8">
                    <!-- Portfolio Chart-->
                    <div class="row">
                        <div class="col-sm-12">
                            <div class="panel widget">
                                <div class="panel-heading">
                                    <div class="row">
                                        <div id="portfoliochart" style="height:200px"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <!-- Project Chart-->
                    <div class="row">
                        <div class="col-sm-12">
                            <div class="panel widget">
                                <div class="panel-heading">
                                    <div class="row">
                                        <div id="projectchart" style="height:200px"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <!-- Component Chart-->
                    <div class="row">
                        <div class="col-sm-12">
                            <div class="panel widget">
                                <div class="panel-heading">
                                    <div class="row">
                                        <div id="componentchart" style="height:200px"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- Right Column -->
                <div class="col-lg-4">
                    <!-- Ratios (Progress Bars) -->
                    <div class="row">
                        <div class="col-sm-12">
                            <div class="panel widget">
                                <div class="panel-heading">
                                    <div class="row">
                                        <div class="col-xs-12">
                                            <h4>Vulnerable Project Ratio</h4>
                                            <div class="progress">
                                                <div id="vulnerableProjects" class="progress-bar progress-bar-danger" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="min-width:2em; width:0">
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-xs-12">
                                            <h4>Vulnerable Component Ratio</h4>
                                            <div class="progress">
                                                <div id="vulnerableComponents" class="progress-bar progress-bar-danger" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="min-width:2em; width:0">
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <!-- Projects at Risk -->
                    <div class="row">
                        <div class="col-sm-12">
                            <div class="panel widget">
                                <div class="panel-heading">
                                    <div class="row">
                                        <div class="col-xs-3">
                                            <i class="fa fa-thermometer-half  fa-5x"></i>
                                        </div>
                                        <div class="col-xs-9 text-right">
                                            <div class="huge"><span id="projectsAtRisk"></span></div>
                                            <div>Projects at Risk</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <!-- Vulnerability Database Trend -->
                    <div class="row">
                        <div class="col-sm-12">
                            <div class="panel widget">
                                <div class="panel-heading">
                                    <div class="row">
                                        <div id="vulnerabilitychart" style="height:200px"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <!-- Statistics -->
                    <div class="row">
                        <div class="col-sm-12">
                            <div class="panel widget">
                                <div class="panel-heading">
                                    <div class="row">
                                        <table width="100%" class="table widget-table">
                                            <tr>
                                                <td>Projects (total):</td>
                                                <td><span id="statTotalProjects"></span></td>
                                            </tr>
                                            <tr>
                                                <td>Vulnerable Projects:</td>
                                                <td><span id="statVulnerableProjects"></span></td>
                                            </tr>
                                            <tr>
                                                <td>Components (total):</td>
                                                <td><span id="statTotalComponents"></span></td>
                                            </tr>
                                            <tr>
                                                <td>Vulnerable Components:</td>
                                                <td><span id="statVulnerableComponents"></span></td>
                                            </tr>
                                            <tr>
                                                <td>Portfolio Vulnerabilities:</td>
                                                <td><span id="statPortfolioVulnerabilities"></span></td>
                                            </tr>
                                            <tr>
                                                <td>Last Measurement:</td>
                                                <td><span id="statLastMeasurement"></span>&nbsp;&nbsp;<span id="refresh"><i class="fa fa-refresh" aria-hidden="true"></i></span></td>
                                            </tr>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div> <!-- /widget-row> -->

        </div>
    </div>
    <jsp:include page="/WEB-INF/fragments/common-modals.jsp"/>
</div>
<jsp:include page="/WEB-INF/fragments/footer.jsp"/>
<script type="text/javascript" src="<c:url value="/functions.js"/>"></script>
</body>
</html>
