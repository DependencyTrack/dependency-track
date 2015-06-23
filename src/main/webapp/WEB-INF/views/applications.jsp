<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

<div id="applicationContainer">
    <c:if test="${!empty applicationList}">

        <table id="applicationTable" class="list">
            <c:forEach items="${applicationList}" var="application">
                <tr>
                    <td id="applicationCaret>${application.id}" data-toggle="collapse" data-target="#applicationDetails${application.id}" style="vertical-align:top;width:20px;height:20px;"><span class="caret"></span></td>
                    <td style="vertical-align:top;"><a href="javascript:void(0);" data-toggle="collapse" data-target="#applicationDetails${application.id}"><e:forHtmlContent value="${application.name}"/></a>
                        <div id="applicationDetails${application.id}" class="collapse">

                            <table id="applicationTable-${application.id}" class="innerlist">

                             <c:if  test="${!check}">
                                <c:forEach items="${application.versions}" var="version">
                                    <tr>
                                        <td><span class="badge <c:if test="${version.vulnCount > 0}">badge-important</c:if>"><e:forHtmlContent value="${version.vulnCount}"/></span></td>
                                        <td><a href="applicationVersion/${version.id}"><e:forHtmlContent value="${version.version}"/></a></td>
                                    </tr>
                                 </c:forEach>
                             </c:if>

                            <c:if test="${check}">
                                <c:if test="${!empty versionlist}">
                                    <c:forEach items="${versionlist}" var="verv">
                                        <c:if  test="${application.id eq verv.application.id}">
                                            <tr>
                                                <td><span class="badge <c:if test="${version.vulnCount > 0}">badge-important</c:if>"><e:forHtmlContent value="${verv.vulnCount}"/></span></td>
                                                <td><a href="applicationVersion/${verv.id}"><e:forHtmlContent value="${verv.version}"/></a></td>
                                            </tr>
                                        </c:if>
                                    </c:forEach>
                                </c:if>
                            </c:if>

                            </table>
                        </div>
                    </td>
                    <c:if  test="${!check}">

                        <td style="vertical-align:top;">${fn:length(application.versions)}</td>
                        <%--<td style="vertical-align:top;">
                            <span class="output">0</span>

                        </td>--%>

                    <td style="vertical-align:top;text-align:right;">
                        <spring:message code="permissions.cloneApplication" var="cloneApplication"/>
                        <spring:message code="permissions.addApplicationVersion" var="addApplicationVersion"/>
                        <spring:message code="permissions.updateApplication" var="updateApplication"/>

                        <div class="btn-group">
                            <shiro:hasPermission name="${cloneApplication}">
                            <a data-toggle="modal" data-id="${application.id}" class="open-CloneApplicationModal btn" href="#cloneApplicationModal"><spring:message code="label.application.clone"/></a>
                            </shiro:hasPermission>
                            <shiro:hasPermission name="${addApplicationVersion}">
                            <a data-toggle="modal" data-id="${application.id}" class="open-AddApplicationVersionModal btn" href="#addApplicationVersionModal"><spring:message code="label.version.add"/></a>
                            </shiro:hasPermission>
                            <shiro:hasPermission name="${updateApplication}">
                            <a data-toggle="modal" data-id="${application.id}" data-name="${e:forHtmlAttribute(application.name)}" class="open-EditApplicationModal btn" href="#editApplicationModal"><spring:message code="label.edit"/></a>
                            </shiro:hasPermission>
                        </div>


                    </td>
                </tr>
            </c:if>
            </c:forEach>
        </table>
    </c:if>
    <c:if  test="${empty applicationList}">
        <p><spring:message code="label.empty.search.results"/></p>
    </c:if>
</div>

<div id="applicationModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="applicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="applicationModalLabel"><spring:message code="label.application.new"/></h4>
    </div>

    <c:url value="/addApplication" var="addApplicationUrl"/>
    <form:form id="addApplicationForm" style="margin-bottom:0" action="${addApplicationUrl}" method="post" autocomplete="off">
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

    <c:url value="/updateApplication" var="updateApplicationUrl"/>
    <form:form id="editApplicationForm" style="margin-bottom:0" action="${updateApplicationUrl}" method="post" autocomplete="off">
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

    <c:url value="/addApplicationVersion" var="addApplicationVersionUrl"/>
    <form:form id="addApplicationVersionForm" style="margin-bottom:0" action="${addApplicationVersionUrl}" method="post" autocomplete="off">
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

    <c:url value="/cloneApplication" var="cloneApplicationUrl"/>
    <form:form id="cloneApplicationForm" style="margin-bottom:0" action="${cloneApplicationUrl}" method="post" autocomplete="off">
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