<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>${properties.longname}: ${param.title}</title>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta charset="utf-8">
    <meta name="copyright" content="&#169; 2013 Axway. All rights reserved."/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="<c:url value="${pageContext.request.contextPath}/resources/favicon.ico"/>" />
    <link rel="stylesheet" type="text/css" href="<c:url value="${pageContext.request.contextPath}/resources/bootstrap/css/bootstrap.min.css"/>" media="screen"/>
    <link rel="stylesheet" type="text/css" href="<c:url value="${pageContext.request.contextPath}/resources/style.css"/>" />
    <link rel="stylesheet" type="text/css" href="<c:url value="${pageContext.request.contextPath}/resources/tablesorter/style.css"/>" />
    <script type="text/javascript" src="<c:url value="${pageContext.request.contextPath}/resources/jquery-1.10.2.min.js"/>"></script>
    <script type="text/javascript" src="<c:url value="${pageContext.request.contextPath}/resources/jquery.chained.min.js"/>"></script>
    <script type="text/javascript" src="<c:url value="${pageContext.request.contextPath}/resources/tablesorter/jquery.tablesorter.min.js"/>"></script>
    <script type="text/javascript" src="<c:url value="${pageContext.request.contextPath}/resources/bootstrap/js/bootstrap.min.js"/>"></script>
    <script type="text/javascript" src="<c:url value="${pageContext.request.contextPath}/resources/functions.js"/>"></script>
</head>
<body>

<jsp:include page="/WEB-INF/views/templates/header.jsp"/>

<div class="navbar navbar-static-top">
    <div class="navbar-inner">
        <ul class="nav">
            <li class="<c:if test="${param.content!='applications'}">in</c:if>active"><a href="<c:url value="${pageContext.request.contextPath}/applications"/>"><spring:message code="navbar.applications"/></a></li>
            <li class="<c:if test="${param.content!='libraries'}">in</c:if>active"><a href="<c:url value="${pageContext.request.contextPath}/libraries"/>"><spring:message code="navbar.libraries"/></a></li>
            <li class="<c:if test="${param.content!='about'}">in</c:if>active"><a href="<c:url value="${pageContext.request.contextPath}/about"/>"><spring:message code="navbar.about"/></a></li>
        </ul>
    </div>
</div>

<jsp:include page="/WEB-INF/views/templates/container.jsp"/>

<jsp:include page="/WEB-INF/views/templates/footer.jsp"/>
</body>
</html>