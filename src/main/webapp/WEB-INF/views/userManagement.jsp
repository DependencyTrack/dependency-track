<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>


<div id="userManagaementContainer">

   <div class="row-fluid">
      <div class="span12 well-small">
            <table class="table">
            <thead>
            <tr>
                <th><spring:message code="label.Schedule"/></th>

                <th><spring:message code="lable.Slider"/></th>
                <th><spring:message code="label.Schedule.Value"/></th>

            </tr>
            </thead>
            <tbody>
            <tr>
            <td><spring:message code="label.globalSchedule"/></td>
            <td> <input class="slider" id ="slider" type="range" min="5" max="25" value="5" step="10"  /></td>
            <td><input class="box" id = "box"  type="text" value="5" style="width:20px;"/></td>
            </tr>
            </tbody>
             </table>
          </div>
   </div>

    <div class="hero-unit">
    <p> <spring:message code="label.globalSchedule"/></p>
    </div>

    <c:if test="${!empty userList}">

        <table class="table table-hover">
            <thead>
            <tr>
                <th><spring:message code="label.username"/></th>

                <th><spring:message code="label.userRole"/></th>
                <th><spring:message code="label.delete"/></th>

            </tr>
            </thead>
            <tbody>
            <c:forEach items="${userList}" var="userList">
                <tr>
                    <td>${userList.username}</td>

                    <td>
                        <select id="rolenamenameid" data-userid='${userList.id}' name="rolename" class="rolename" autofocus="autofocus">
                        <c:forEach items="${roleList}" var="roleList">
                            <c:choose>
                            <c:when test="${roleList.id == userList.roles.id}">
                                <option value="${roleList.id}" selected="selected" >${roleList.role}</option>
                            </c:when>
                            <c:otherwise>
                                <option value="${roleList.id} ">${roleList.role}</option>
                            </c:otherwise>
                            </c:choose>
                        </c:forEach>
                        </select>
                    </td>
                    <td>
                      <img  class="deleteUser" data-userid='${userList.id}' src="${pageContext.request.contextPath}/resources/images/deleteIcon.ico" alt="Delete" height="20" width="20">
                    </td>
                </tr>
            </c:forEach>
            </tbody>
        </table>
    </c:if>
</div>


<div id="registerUserModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="registerUserModalLabel" aria-hidden="true"
     data-backdrop="static" data-keyboard="false">
    <div class="modal-header" >
        <h4 id="registerUserModalLabel"><spring:message code="login.create.account"/></h4>
    </div>

    <c:url value="/registerUser" var="registerUserUrl"/>
    <form:form id="registerUserForm" style="margin-bottom:0" action="${registerUserUrl}" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="username"><spring:message code="label.username"/></label></td>
                    <td><input id="username" name="username" type="text" autofocus="autofocus" pattern=".{5,}" title="5 characters minimum" required="required"/></td>
                </tr>
                <tr>
                    <td><label for="password"><spring:message code="label.password"/></label></td>
                    <td><input id="password" name="password" type="password" pattern=".{8,}" title="8 characters minimum" required="required"/></td>
                </tr>
                <tr>
                    <td><label for="chkpassword"><spring:message code="label.password.confirm"/></label></td>
                    <td><input id="chkpassword" name="chkpassword" type="password" pattern=".{8,}" title="8 characters minimum" required="required"/></td>
                </tr>
                <td><label for="adminrolenamenameid"><spring:message code="label.userRole"/></label></td>
                <td>
                <select id="adminrolenamenameid" name="role" class="role" autofocus="autofocus">
                        <c:forEach items="${roleList}" var="roleList">
                            <option value="${roleList.id} ">${roleList.role}</option>
                        </c:forEach>
                </select>
                        </td>
                    <tr>

                </tr>
            </table>
        </div>
        <div class="modal-footer">
            <button class="btn " data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.register"/></button>
        </div>
    </form:form>
</div>