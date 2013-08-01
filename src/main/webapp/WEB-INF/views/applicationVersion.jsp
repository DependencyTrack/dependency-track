<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>

<div id="applicationVersionContainer">
    <c:if test="${!empty applicationVersion}">

        <table id="applicationVersionTable" class="list tablesorter">
            <thead>
            <tr>
                <th>Vendor</th>
                <th>Library Name</th>
                <th>Library Version</th>
                <th></th>
            </tr>
            </thead>
            <tbody>
            <c:forEach items="${dependencies}" var="libraryVersion">
            <tr>
                <td style="vertical-align:middle;">${libraryVersion.library.libraryVendor.vendor}</td>
                <td style="vertical-align:middle;">${libraryVersion.library.libraryname}</td>
                <td style="vertical-align:middle;">${libraryVersion.libraryversion}</td>
                <td style="width:100px;vertical-align:middle;text-align:right;">
                    <a class="btn btn-danger header-button" id="deleteLink" href="${pageContext.request.contextPath}/deleteDependency?appversionid=${applicationVersion.id}&versionid=${libraryVersion.id}" onclick="return confirm('Are you sure you want to delete the dependency on this library?')">Delete</a>
                </td>
            </tr>
            </c:forEach>
            </tbody>
        </table>
    </c:if>
</div>

<div id="addDependencyModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="addDependencyModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="addDependencyModalLabel">New Dependency</h4>
    </div>
    <form:form id="addApplicationForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/addDependency" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="adddepvendor">Vendor</label></td>
                    <td>
                        <select id="adddepvendor" name="vendor" autofocus="autofocus" required="required">
                            <option value="">--</option>
                            <c:forEach items="${libraryVendors}" var="libraryVendor">
                                <option value="${libraryVendor.vendor}">${libraryVendor.vendor}</option>
                            </c:forEach>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td><label for="adddeplibrary">Library</label></td>
                    <td>
                        <select id="adddeplibrary" name="library" autofocus="autofocus" required="required">
                            <option value="">--</option>
                            <c:forEach items="${libraryVendors}" var="libraryVendor">
                                <c:forEach items="${libraryVendor.libraries}" var="library">
                                    <option value="${library.libraryname}" class="${libraryVendor.vendor}">${library.libraryname}</option>
                                </c:forEach>
                            </c:forEach>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td><label for="adddepversion">Version</label></td>
                    <td>
                        <select id="adddepversion" name="versionid" autofocus="autofocus" required="required">
                            <option value="">--</option>
                            <c:forEach items="${libraryVendors}" var="libraryVendor">
                                <c:forEach items="${libraryVendor.libraries}" var="library">
                                    <c:forEach items="${library.versions}" var="version">
                                        <option value="${version.id}" class="${library.libraryname}">${version.libraryversion}</option>
                                    </c:forEach>
                                </c:forEach>
                            </c:forEach>
                        </select>
                    </td>
                </tr>
            </table>
            <input type="hidden" id="addappversionid" name="appversionid" value="${applicationVersion.id}"/>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Add Dependency</button>
        </div>
    </form:form>
</div>

  <%--cloning individual application version--%>
<div id="cloneVersionModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="cloneVersionModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="cloneVersionModalLabel">Enter New Version Number</h4>
    </div>
    <%--add link to controller--%>
    <form:form id="cloneVersionForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/cloneApplicationVersion" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="cloneVersionNumber">Version Number</label></td>
                    <td><input id="cloneVersionNumber" name="cloneVersionNumber" type="text" autofocus="autofocus" required="required"/></td>
                </tr>
            </table>
            <input type="hidden" id="applicationid" name="applicationid" value=""/>
            <input type="hidden" id="applicationversion" name="applicationversion" value=""/>

        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Clone</button>
        </div>
    </form:form>
</div>

<div id="editDependencyModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="editDependencyModal" aria-hidden="true">
    <div class="modal-header">
        <h4 id="editDependencyModalLabel">Update Application Version
          <span class="delete-span">
				<a class="btn btn-danger header-button" href="" id="deleteAppVer"  onclick="return confirm('Are you sure you want to delete this version') ">Delete</a>
			</span>
        </h4>
    </div>
    <form:form id="addApplicationForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/updateApplicationVersion" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="editappver">Version</label></td>
                    <td><input id="editappver" name="editappver" type="text" value=""/></td>

                </tr>


            </table>
            <input type="hidden" id="appversionid" name="appversionid" value="${applicationVersion.id}"/>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Update</button>
        </div>
    </form:form>
</div>