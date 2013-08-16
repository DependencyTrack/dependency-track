<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>




  


       
<c:if test="${errorMessage != null}">
<b class="error">${errorMessage}</b>
</c:if>
       
       <form:form name="login" method="POST">
       <div class="table">
           <div class="table_row">
              <div>Username:</div><div><input name="username" value="" type="text" required="required"/></div>
           </div>
           <div class="table_row">
              <div>Password:</div><div><input name="password" value="" type="password" required="required"/></div>
           </div>
           <div class="table_row">
                  <input name="submit" class="btn btn-primary" value="Login" type="submit"/>
           </div>
           <div class="table_row">
              <div> </div> <a data-toggle="modal" class="btn" href="#registerUserModal"><c:out value="Register"/></a></div>
           </div>
       </div>
       </form:form>

<div id="registerUserModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="registerUserModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="registerUserModalLabel"><c:out value="Register New User"/></h4>
    </div>
    <form:form id="registerUserForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/registerUser" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="username"><c:out value="User Name"/></label></td>
                    <td><input id="username" name="username" type="text" autofocus="autofocus" required="required"/></td>
                </tr>
                <tr>
                    <td><label for="password"><c:out value="Password"/></label></td>
                    <td><input id="password" name="password" type="password" required="required"/></td>
                </tr>
                <tr>
                    <td><label for="chkpassword"><c:out value="Confirm Password"/></label></td>
                    <td><input id="chkpassword" name="chkpassword" type="password" required="required"/></td>
                </tr>
            </table>
        </div>
        <div class="modal-footer">
            <button class="btn " data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><c:out value="Register"/></button>
        </div>
    </form:form>
</div>
