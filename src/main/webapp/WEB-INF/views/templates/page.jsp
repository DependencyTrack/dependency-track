<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%--
  ~ Copyright 2013 Axway
  ~
  ~ This file is part of OWASP Dependency-Track.
  ~
  ~ Dependency-Track is free software: you can redistribute it and/or modify it under the terms of the
  ~ GNU General Public License as published by the Free Software Foundation, either version 3 of the
  ~ License, or (at your option) any later version.
  ~
  ~ Dependency-Track is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
  ~ even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
  ~ Public License for more details.
  ~
  ~ You should have received a copy of the GNU General Public License along with Dependency-Track.
  ~ If not, see http://www.gnu.org/licenses/.
  --%>

<!DOCTYPE html>
<html lang="en">
<head>
    <title><c:out value="${properties.longname}: ${param.title}"/></title>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta charset="utf-8">
    <meta name="copyright" content="&#169; 2013 Axway. All rights reserved."/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="<c:url value="${pageContext.request.contextPath}/resources/favicon.ico"/>"/>
    <link rel="stylesheet" type="text/css"
          href="<c:url value="${pageContext.request.contextPath}/resources/bootstrap/css/bootstrap.min.css"/>"
          media="screen"/>
    <link rel="stylesheet" type="text/css"
          href="<c:url value="${pageContext.request.contextPath}/resources/style.css"/>"/>
    <link rel="stylesheet" type="text/css"
          href="<c:url value="${pageContext.request.contextPath}/resources/tablesorter/style.css"/>"/>
    <script type="text/javascript"
            src="<c:url value="${pageContext.request.contextPath}/resources/jquery-1.10.2.min.js"/>"></script>
    <script type="text/javascript"
            src="<c:url value="${pageContext.request.contextPath}/resources/jquery.chained.min.js"/>"></script>
    <script type="text/javascript"
            src="<c:url value="${pageContext.request.contextPath}/resources/tablesorter/jquery.tablesorter.min.js"/>"></script>
    <script type="text/javascript"
            src="<c:url value="${pageContext.request.contextPath}/resources/bootstrap/js/bootstrap.min.js"/>"></script>
    <script type="text/javascript"
            src="<c:url value="${pageContext.request.contextPath}/resources/functions.js"/>"></script>
</head>
<body>

<jsp:include page="/WEB-INF/views/templates/header.jsp"/>

<div class="navbar navbar-static-top">
    <div class="navbar-inner">
        <ul class="nav">
            <li class="<c:if test="${param.content!='applications'}">in</c:if>active"><a
                    href="<c:url value="${pageContext.request.contextPath}/applications"/>">Applications</a></li>
            <li class="<c:if test="${param.content!='libraries'}">in</c:if>active"><a
                    href="<c:url value="${pageContext.request.contextPath}/libraries"/>">Libraries</a></li>
            <li><a data-toggle="modal" class="open-SearchApplicationModal" href="#searchApplicationModal">Search</a>
            </li>
            <li class="<c:if test="${param.content!='about'}">in</c:if>active"><a
                    href="<c:url value="${pageContext.request.contextPath}/about"/>">About</a></li>
        </ul>
    </div>
</div>

<jsp:include page="/WEB-INF/views/templates/container.jsp"/>

<jsp:include page="/WEB-INF/views/templates/footer.jsp"/>

<div id="searchApplicationModal" class="modal hide fade" tabindex="-1" role="dialog"
     aria-labelledby="searchApplicationModal" aria-hidden="true">
    <div class="modal-header">
        <h4 id="searchApplicationModalLabel">Search Application
        </h4>
    </div>
    <form:form id="searchApplicationForm" style="margin-bottom:0"
               action="${pageContext.request.contextPath}/searchApplication" method="post" autocomplete="off">
        <div class="modal-body">
            <table>

                <tr>
                    <td><label for="serappven">Library Vendor</label></td>
                    <td><select id="serappven" name="serappven" autofocus="autofocus" required="required">
                        <option value="">--</option>
                    </select></td>
                        <%--<td><input id="serapplib" name="serapplib" type="text" value=""/></td>--%>
                </tr>

                <tr>
                    <td><label for="serapplib">Library Name</label></td>
                    <td><select id="serapplib" name="serapplib" autofocus="autofocus" required="required">
                        <option value="">--</option>
                    </select></td>
                        <%--<td><input id="serapplib" name="serapplib" type="text" value=""/></td>--%>
                </tr>
                <tr>
                    <td><label for="serapplibver">Library Version</label></td>

                    <td><select id="serapplibver" name="serapplibver" autofocus="autofocus">
                        <option value="">--</option>
                    </select></td>
                </tr>

            </table>

        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Search</button>
        </div>
    </form:form>
</div>
</body>
</html>