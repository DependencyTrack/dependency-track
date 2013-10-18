<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>


<div id="userManagaementContainer">
    <c:if test="${!empty userList}">
        <table class="table table-hover">
            <thead>
            <tr>
                <th><spring:message code="label.username"/></th>
                <th><spring:message code="label.validUser"/></th>
                <th><spring:message code="label.userRole"/></th>
                <th><spring:message code="label.delete"/></th>

            </tr>
            </thead>
            <tbody>
            <c:forEach items="${userList}" var="userList">
                <tr>
                    <td>${userList.username}</td>
                    <td>
                        <c:choose>
                            <c:when test="${userList.checkvalid}">
                                <input type="checkbox" name="checkvalidity" class="checkvalidity" value="${userList.id}"
                                               checked/>
                            </c:when>
                            <c:otherwise>
                                <input type="checkbox" name="checkvalidity" class="checkvalidity" value="${userList.id}"/>
                            </c:otherwise>
                        </c:choose>
                    </td>
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
            </table>
        </div>
        <div class="modal-footer">
            <button class="btn " data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.register"/></button>
        </div>
    </form:form>
</div>