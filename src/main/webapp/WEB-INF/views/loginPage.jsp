<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<spring:message code="label.username" var="usernameLabel"/>
<spring:message code="label.password" var="passwordLabel"/>

<!DOCTYPE html>
<html lang="en">
<head>
    <title><c:out value="${properties.longname}"/></title>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta charset="utf-8">
    <meta name="copyright" content="&#169; 2013 Axway. All rights reserved."/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="<c:url value="/resources/favicon.ico"/>"/>
    <link rel="stylesheet" type="text/css" href="<c:url value = "/resources/bootstrap/css/bootstrap.min.css"/>" media="screen"/>
    <link rel="stylesheet" type="text/css" href="<c:url value="/resources/style.css"/>"/>
    <script type="text/javascript" src="<c:url value="/resources/jquery-1.10.2.min.js"/>"></script>
    <script type="text/javascript" src="<c:url value="/resources/bootstrap/js/bootstrap.min.js"/>"></script>
    <script type="text/javascript" src="<c:url value="/resources/functions.js"/>"></script>
</head>
<body>

<div id="login-block">
    <h3><c:out value="${properties.longname}"/></h3>
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
            <div class="login-links">
                <a data-toggle="modal" href="#registerUserModal"><spring:message code="login.account.question"/> <strong><spring:message code="login.signup"/></strong></a>
            </div>
        </div>
    </div>
</div>



<div id="registerUserModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="registerUserModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="registerUserModalLabel"><spring:message code="login.create.account"/></h4>
    </div>

    <c:url value="/registerUser" var="registerUserUrl"/>
    <form:form id="registerUserForm" style="margin-bottom:0" action="${registerUserUrl}" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="username"><spring:message code="label.username"/></label></td>
                    <td><input id="username" name="username" type="text" autofocus="autofocus" required="required"/></td>
                </tr>
                <tr>
                    <td><label for="password"><spring:message code="label.password"/></label></td>
                    <td><input id="password" name="password" type="password" required="required"/></td>
                </tr>
                <tr>
                    <td><label for="chkpassword"><spring:message code="label.password.confirm"/></label></td>
                    <td><input id="chkpassword" name="chkpassword" type="password" required="required"/></td>
                </tr>
            </table>
        </div>
        <div class="modal-footer">
            <button class="btn " data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.register"/></button>
        </div>
    </form:form>
</div>

</body>
</html>