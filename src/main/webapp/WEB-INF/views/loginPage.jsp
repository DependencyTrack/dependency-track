<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>
<spring:message code="label.username" var="usernameLabel"/>
<spring:message code="label.password" var="passwordLabel"/>

<!DOCTYPE html>
<html lang="en">
<head>
    <title><e:forHtmlContent value="${properties.longname}"/></title>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta charset="utf-8">
    <meta name="copyright" content="Copyright Axway. All rights reserved."/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="<c:url value="/resources/favicon.ico"/>"/>
    <link rel="stylesheet" type="text/css" href="<c:url value = "/resources/bootstrap/css/bootstrap.min.css"/>" media="screen"/>
    <link rel="stylesheet" type="text/css" href="<c:url value="/resources/style.css"/>"/>
    <script type="text/javascript" src="<c:url value="/resources/jquery-1.10.2.min.js"/>"></script>
    <script type="text/javascript" src="<c:url value="/resources/bootstrap/js/bootstrap.min.js"/>"></script>
    <script type="text/javascript" src="<c:url value="/resources/functions.js"/>"></script>
</head>
<body class="login-page">

<div id="login-block">
    <h3><e:forHtmlContent value="${properties.longname}"/></h3>
    <div class="login-box clearfix">
        <div class="login-logo">
            <img src="<c:url value="/resources/images/OWASP-logo-100x100.png"/>" alt="OWASP Logo"/>
        </div>
        <hr />
        <div class="login-form">
        <c:if  test="${authenticationException}">
            <div class="alert alert-error">
                <button type="button" class="close" data-dismiss="alert">&times;</button>
                <h4><spring:message code="login.failure"/></h4>
                <spring:message code="login.failure.message"/>
            </div>
        </c:if>

            <c:url value="/login" var="loginUrl"/>
            <form:form id="loginForm" action="${loginUrl}" method="post">
                <input type="text" name="username" placeholder="${usernameLabel}" required="required"/>
                <input type="password" name="password" placeholder="${passwordLabel}" required="required" autocomplete="off"/>
                <button type="submit" class="btn btn-primary btn-login"><spring:message code="login.button"/></button>
            </form:form>
        </div>
    </div>
</div>

</body>
</html>