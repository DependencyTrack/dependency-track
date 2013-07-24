<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@include file="/WEB-INF/views/templates/header.jsp" %>
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