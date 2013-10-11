<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>


<div id="userManagaementContainer">
    <c:if test="${!empty userList}">
        <table class="table table-hover">
            <thead>
            <tr>
                <th><spring:message code="label.username"/></th>
                <th><spring:message code="label.validUser"/></th>
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
                                 <input type="checkbox" name="checkvalidity" class="checkvalidity" value="${userList.id}"
                                    />
                            </c:otherwise>
                        </c:choose>
                    </td>
                    <td >
                      <img  class="deleteUser" data-userid='${userList.id}' src="${pageContext.request.contextPath}/resources/images/deleteIcon.ico" alt="Delete" height="20" width="20">
                    </td>

                </tr>
            </c:forEach>
            </tbody>
        </table>
    </c:if>
</div>
