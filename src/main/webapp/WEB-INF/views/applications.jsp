<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>

<div id="applicationContainer">
    <c:if test="${!empty applicationList}">

        <table id="applicationTable" class="list">
            <tr>
                <th></th>
                <th><spring:message code="label.name"/></th>
                <th><spring:message code="label.versions"/></th>
                <th></th>
            </tr>
            <c:forEach items="${applicationList}" var="application">
                <tr>
                    <td id="applicationCaret>${application.id}" data-toggle="collapse" data-target="#applicationDetails${application.id}" style="vertical-align:top;width:20px;height:20px;"><span class="caret"></span></td>
                    <td style="vertical-align:top;"><a href="javascript:void(0);" data-toggle="collapse" data-target="#applicationDetails${application.id}"><c:out value="${application.name}"/></a>
                        <div id="applicationDetails${application.id}" class="collapse">
                            <ul class="nav nav-list">
                                <li class="nav-header"><spring:message code="label.versions"/></li>
                            <c:forEach items="${application.versions}" var="version">
                                <li><a href="applicationVersion/${version.id}"><c:out value="${version.version}"/></a></li>
                            </c:forEach>
                            </ul>
                        </div>
                    </td>
                    <td style="vertical-align:top;">${fn:length(application.versions)}</td>
                    <td style="vertical-align:top;text-align:right;">
                        <div class="btn-group">
                            <a data-toggle="modal" data-id="${application.id}" class="open-CloneApplicationModal btn" href="#cloneApplicationModal"><spring:message code="label.application.clone"/></a>
                            <a data-toggle="modal" data-id="${application.id}" class="open-AddApplicationVersionModal btn" href="#addApplicationVersionModal"><spring:message code="label.version.add"/></a>
                            <a data-toggle="modal" data-id="${application.id}" data-name="${application.name}" class="open-EditApplicationModal btn" href="#editApplicationModal"><spring:message code="label.edit"/></a>
                        </div>
                    </td>
                </tr>


            </c:forEach>
        </table>
    </c:if>
</div>

<div id="applicationModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="applicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="applicationModalLabel"><spring:message code="label.application.new"/></h4>
    </div>
    <form:form id="addApplicationForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/addApplication" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="name"><spring:message code="label.name"/></label></td>
                    <td><input id="name" name="name" type="text" autofocus="autofocus" required="required"/></td>
                </tr>
                <tr>
                    <td><label for="version"><spring:message code="label.version"/></label></td>
                    <td><input id="version" name="version" type="text" required="required"/></td>
                </tr>
            </table>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.application.add"/></button>
        </div>
    </form:form>
</div>

<div id="editApplicationModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="editApplicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="editApplicationModalLabel"><spring:message code="label.application.edit"/>
            <span class="delete-span">
                <spring:message code="confirm.delete.application" var="confirmDeleteMessage"/>
				<a class="btn btn-danger header-button" id="deleteLink" href="" onclick="return confirm('${confirmDeleteMessage}')"><spring:message code="label.delete"/></a>
			</span>
        </h4>
    </div>
    <form:form id="editApplicationForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/updateApplication" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="editname"><spring:message code="label.name"/></label></td>
                    <td><input id="editname" name="name" type="text" autofocus="autofocus" required="required" value=""/></td>
                </tr>
            </table>
            <input type="hidden" id="editid" name="id" value=""/>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.saveChanges"/></button>
        </div>
    </form:form>
</div>

<div id="addApplicationVersionModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="addApplicationVersionModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="addApplicationVersionModalLabel"><spring:message code="label.version.add"/></h4>
    </div>
    <form:form id="addApplicationVersionForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/addApplicationVersion" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="addversion"><spring:message code="label.version"/></label></td>
                    <td><input id="addversion" name="version" type="text" autofocus="autofocus" required="required" value=""/></td>
                </tr>
            </table>
            <input type="hidden" id="addid" name="id" value=""/>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.version.add"/></button>
        </div>
    </form:form>
</div>

<div id="cloneApplicationModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="cloneApplicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="cloneApplicationModalLabel"><spring:message code="label.application.clone"/></h4>
    </div>
    <%--add link to controller--%>
    <form:form id="cloneApplicationForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/cloneApplication" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="cloneAppName"><spring:message code="label.name.cloned"/></label></td>
                    <td><input id="cloneAppName" name="cloneAppName" type="text" autofocus="autofocus" required="required"/></td>
                </tr>
            </table>
            <input type="hidden" id="applicationid" name="applicationid" value=""/>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.clone"/></button>
        </div>
    </form:form>
</div>