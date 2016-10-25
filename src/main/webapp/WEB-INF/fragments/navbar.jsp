<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
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
                <li id="nav-about"><a href="#" data-toggle="modal" data-target="#modalAbout"><span class="glyphicon glyphicon-info-sign" aria-hidden="true"></span> About</a></li>
                <li id="nav-admin"><a href="<c:url value="/admin"/>"><span class="glyphicon glyphicon-cog" aria-hidden="true"></span> Admin</a></li>
                <li id="nav-logout"><a href="#" onclick="logout();"><span class="glyphicon glyphicon glyphicon-log-out" aria-hidden="true"></span> Logout</a></li>
            </ul>
        </div>
    </div>
</nav>
