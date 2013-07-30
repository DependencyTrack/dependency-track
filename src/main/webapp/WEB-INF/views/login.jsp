<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@include file="/WEB-INF/views/templates/header.jsp" %>
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
<html>
<head>
<link href="<c:url value="/resources/style.css"/>" rel="stylesheet" type="text/css" />
<link href="<c:url value="/resources/favicon.ico"/>" rel="shortcut icon" type="image/ico" />
   <title>Login</title>
 
</head>
<body>
  
    <div  class="content">
       <h2>Login</h2>
       
<c:if test="${errorMessage != null}">
<b class="error">${errorMessage}</b>
</c:if>
       
       <form:form name="login" method="POST">
       <div class="table">
           <div class="table_row">
              <div>Username:</div><div><input name="username" value="" type="text"/></div>
           </div>
           <div class="table_row">
              <div>Password:</div><div><input name="password" value="" type="password"/></div>
           </div>
           <div class="table_row">
              <div>
                  <input name="submit" value="Login" type="submit"/>
              </div>
           </div>
       </div>
       </form:form>
    </div>
<%@include file="/WEB-INF/views/templates/footer.jsp" %>
</body>
</html>