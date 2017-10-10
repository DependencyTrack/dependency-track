<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <jsp:include page="/WEB-INF/fragments/header.jsp"/>
    <title>OWASP Dependency-Track - Administration</title>
</head>
<body data-sidebar="admin">
<jsp:include page="/WEB-INF/fragments/navbar.jsp"/>
<div class="container-fluid">
    <div class="content-row main">
        <div class="col-sm-12 col-md-12">
            <h3>Administration</h3>
            <div class="panel with-nav-tabs panel-default tight">
                <div class="panel-heading">
                    <ul class="nav nav-tabs">
                        <li class="active"><a href="#teamsTab" data-toggle="tab">Teams</a></li>
                        <li><a href="#ldapUsersTab" data-toggle="tab">LDAP Users</a></li>
                        <li><a href="#managedUsersTab" data-toggle="tab">Managed Users</a></li>
                    </ul>
                </div>
                <div class="panel-body tight">
                    <div class="tab-content">
                        <div class="tab-pane active" id="teamsTab">
                            <div id="teamsToolbar">
                                <div class="form-inline" role="form">
                                    <button id="createTeamButton" class="btn btn-default" data-toggle="modal" data-target="#modalCreateTeam"><span class="fa fa-plus"></span> Create Team</button>
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
                                </tr>
                                </thead>
                            </table>
                        </div>
                        <div class="tab-pane" id="ldapUsersTab">
                            <div id="ldapUsersToolbar">
                                <div class="form-inline" role="form">
                                    <button id="createLdapUserButton" class="btn btn-default" data-toggle="modal" data-target="#modalCreateLdapUser"><span class="fa fa-plus"></span> Create User</button>
                                </div>
                            </div>
                            <table id="ldapUsersTable" class="table table-hover detail-table" data-toggle="table"
                                   data-url="<c:url value="/api/v1/user/ldap"/>" data-response-handler="formatLdapUserTable"
                                   data-show-refresh="true" data-show-columns="true" data-search="true"
                                   data-detail-view="true" data-detail-formatter="ldapUserDetailFormatter"
                                   data-toolbar="#ldapUsersToolbar" data-click-to-select="true" data-height="100%">
                                <thead>
                                <tr>
                                    <th data-align="left" data-field="username">Username</th>
                                    <th data-align="left" data-field="dn">Distinguished Name</th>
                                    <th data-align="left" data-field="teamsNum">Teams</th>
                                </tr>
                                </thead>
                            </table>
                        </div>
                        <div class="tab-pane" id="managedUsersTab">
                            <div id="managedUsersToolbar">
                                <div class="form-inline" role="form">
                                    <button id="createManagedUserButton" class="btn btn-default" data-toggle="modal" data-target="#modalCreateManagedUser"><span class="fa fa-plus"></span> Create User</button>
                                </div>
                            </div>
                            <table id="managedUsersTable" class="table table-hover detail-table" data-toggle="table"
                                   data-url="<c:url value="/api/v1/user/managed"/>" data-response-handler="formatManagedUserTable"
                                   data-show-refresh="true" data-show-columns="true" data-search="true"
                                   data-detail-view="true" data-detail-formatter="managedUserDetailFormatter"
                                   data-toolbar="#managedUsersToolbar" data-click-to-select="true" data-height="100%">
                                <thead>
                                <tr>
                                    <th data-align="left" data-field="username">Username</th>
                                    <th data-align="left" data-field="email">Email</th>
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

    <div class="modal fade" id="modalCreateLdapUser" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Create LDAP User</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="sr-only" for="createLdapUserNameInput">Username</label>
                        <input type="text" name="username" placeholder="LDAP username..." class="form-control" id="createLdapUserNameInput">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="createLdapUserCreateButton">Create</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="modalCreateManagedUser" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-md" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h4 class="modal-title">Create Managed User</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="sr-only" for="createManagedUserNameInput">Username</label>
                        <input type="text" name="username" placeholder="Username..." class="form-control" id="createManagedUserNameInput">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" data-dismiss="modal" id="createManagedUserCreateButton">Create</button>
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
    <jsp:include page="/WEB-INF/fragments/common-modals.jsp"/>
</div>
<jsp:include page="/WEB-INF/fragments/footer.jsp"/>
<script type="text/javascript" src="<c:url value="/admin/functions.js"/>"></script>
</body>
</html>