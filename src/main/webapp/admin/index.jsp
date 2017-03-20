<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <jsp:include page="/WEB-INF/fragments/header.jsp"/>
    <title>OWASP Dependency-Track - Administration</title>
</head>
<body>
<jsp:include page="/WEB-INF/fragments/navbar.jsp"/>
<div class="container-fluid">
    <div class="row">
        <div class="col-sm-12 col-md-12 main" id="main">
            <h3>Administration</h3>
            <div class="panel with-nav-tabs panel-default tight">
                <div class="panel-heading">
                    <ul class="nav nav-tabs">
                        <li class="active"><a href="#teamsTab" data-toggle="tab">Teams</a></li>
                        <li><a href="#usersTab" data-toggle="tab">LDAP Users</a></li>
                    </ul>
                </div>
                <div class="panel-body tight">
                    <div class="tab-content">
                        <div class="tab-pane active" id="teamsTab">
                            <div id="teamsToolbar">
                                <div class="form-inline" role="form">
                                    <button id="createTeamButton" class="btn btn-default" data-toggle="modal" data-target="#modalCreateTeam"><span class="glyphicon glyphicon-plus"></span> Create Team</button>
                                </div>
                            </div>
                            <table id="teamsTable" class="table table-hover detail-table" data-toggle="table"
                                   data-url="<c:url value="/api/v1/team"/>" data-response-handler="formatTeamTable"
                                   data-show-refresh="true" data-show-columns="true" data-search="true"
                                   data-detail-view="true" data-detail-formatter="teamDetailFormatter"
                                   data-toolbar="#teamsToolbar" data-click-to-select="true" data-height="100%">
                                <thead>
                                <tr>
                                    <th data-align="left" data-field="name">Team Name</th>
                                    <th data-align="left" data-field="apiKeysNum">API Keys</th>
                                    <th data-align="left" data-field="membersNum">Members</th>
                                    <th data-align="left" data-field="hakmasterIcon">Hakmaster</th>
                                </tr>
                                </thead>
                            </table>
                        </div>
                        <div class="tab-pane" id="usersTab">
                            <div id="usersToolbar">
                                <div class="form-inline" role="form">
                                    <button id="createUserButton" class="btn btn-default" data-toggle="modal" data-target="#modalCreateUser"><span class="glyphicon glyphicon-plus"></span> Create User</button>
                                </div>
                            </div>
                            <table id="usersTable" class="table table-hover detail-table" data-toggle="table"
                                   data-url="<c:url value="/api/v1/user"/>" data-response-handler="formatUserTable"
                                   data-show-refresh="true" data-show-columns="true" data-search="true"
                                   data-detail-view="true" data-detail-formatter="userDetailFormatter"
                                   data-toolbar="#usersToolbar" data-click-to-select="true" data-height="100%">
                                <thead>
                                <tr>
                                    <th data-align="left" data-field="username">Username</th>
                                    <th data-align="left" data-field="dn">Distinguished Name</th>
                                    <th data-align="left" data-field="teamsNum">Teams</th>
                                </tr>
                                </thead>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <jsp:include page="/WEB-INF/fragments/common-modals.jsp"/>

    <!-- Modals specific to administration -->
    <div class="modal fade" id="modalCreateTeam" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Create Team</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="sr-only" for="createTeamNameInput">Team Name</label>
                        <input type="text" name="teamname" placeholder="Team Name..." class="form-control" id="createTeamNameInput">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="createTeamCreateButton">Create</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="modalCreateUser" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Create User</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="sr-only" for="createUserNameInput">Team Name</label>
                        <input type="text" name="username" placeholder="LDAP username..." class="form-control" id="createUserNameInput">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="createUserCreateButton">Create</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="modalAssignTeamToUser" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Assign Team Membership</h4>
                </div>
                <div class="modal-body">
                    <table id="teamsMembershipTable" class="table table-hover" data-toggle="table"
                           data-click-to-select="true" data-height="100%">
                        <thead>
                        <tr>
                            <th data-align="middle" data-field="selected" data-checkbox="true"></th>
                            <th data-align="left" data-field="name">Team Name</th>
                        </tr>
                        </thead>
                    </table>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="assignTeamToUser" data-username="">Update</button>
                </div>
            </div>
        </div>
    </div>

</div>
<jsp:include page="/WEB-INF/fragments/footer.jsp"/>
<script type="text/javascript" src="<c:url value="/admin/functions.js"/>"></script>
</body>
</html>