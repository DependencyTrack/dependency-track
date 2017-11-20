<%@page import="alpine.Config" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%!
    private static final boolean AUTHN_ENABLED = Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHENTICATION);
    private static final boolean AUTHZ_ENABLED = Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHORIZATION);
%>
<nav id="navbar-container" class="navbar navbar-inverse navbar-fixed-top">
    <div class="container-fluid">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <div>
                <a href="<c:url value="/"/>">
                    <img src="<c:url value="/images/dt-icon.svg"/>" style="height:44px; margin-top:4px; margin-right:10px"/>
                    <img src="<c:url value="/images/dt-title.svg"/>" style="height:12px; margin-top:6px;"/>
                </a>
            </div>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
            <ul class="nav navbar-nav navbar-right">
                <li>
                    <div id="smart-search">
                        <input id="smart-search-input" class="typeahead" type="text" placeholder="Search...">
                    </div>
                </li>
                <li id="nav-about"><a href="#" data-toggle="modal" data-target="#modal-about"><span class="fa fa-info-circle" aria-hidden="true"></span> About</a></li>
                <% if(AUTHN_ENABLED) { %>
                <li id="nav-profile"><a href="#" data-toggle="modal" data-target="#modal-profile"><span class="fa fa-user" aria-hidden="true"></span> Profile</a></li>
                <li id="nav-logout"><a href="#" onclick="$common.logout();"><span class="fa fa-sign-out" aria-hidden="true"></span> Logout</a></li>
                <% } %>
            </ul>
        </div>
    </div>
</nav>
<div id="sidebar">
    <ul>
        <li><a href="<c:url value="/"/>" data-toggle="tooltip" data-placement="right" data-sidebar="dashboard" title="Dashboard"><i class="fa fa-area-chart"></i><span>Dashboard</span></a></li>
        <li><a href="<c:url value="/projects/"/>" data-toggle="tooltip" data-placement="right" data-sidebar="projects" title="Projects"><i class="fa fa-sitemap"></i><span>Projects</span></a></li>
        <li><a href="<c:url value="/components/"/>" data-toggle="tooltip" data-placement="right" data-sidebar="components" title="Components"><i class="fa fa-cubes"></i><span>Components</span></a></li>
        <li><a href="<c:url value="/vulnerabilities/"/>" data-toggle="tooltip" data-placement="right" data-sidebar="vulnerabilities" title="Vulnerabilities"><i class="fa fa-shield"></i><span>Vulnerabilities</span></a></li>
        <li><a href="<c:url value="/licenses/"/>" data-toggle="tooltip" data-placement="right" data-sidebar="licenses" title="Licenses"><i class="fa fa-balance-scale"></i><span>Licenses</span></a></li>
        <% if(AUTHN_ENABLED) { %>
        <li><a href="<c:url value="/admin/"/>" data-toggle="tooltip" data-placement="right" data-sidebar="admin" title="Administration"><i class="fa fa-cogs"></i><span>Administration</span></a></li>
        <% } %>
    </ul>
</div>
