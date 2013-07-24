<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div id="librariesContainer">
    <c:if test="${!empty libList}">
        <table class="list tablesorter">
            <thead>
            <tr>
                <th>Vendor</th>
                <th>Library Name</th>
                <th>Library Version</th>
                <th>License</th>
                <th>Language</th>
                <th>Secunia ID</th>

            </tr>
            </thead>
            <tbody>
            <c:forEach items="${libList}" var="libList">
                <tr>
                    <td>${libList.library.libraryVendor.vendor}</td>
                    <td>${libList.library.libraryname}</td>
                    <td>${libList.libraryversion}</td>
                    <td>${libList.library.license.licensename}</td>
                    <td>${libList.library.language}</td>
                    <td>${libList.library.secunia}</td>
                </tr>
            </c:forEach>
            </tbody>
        </table>
    </c:if>
</div>

<div id="libraryModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="applicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="applicationModalLabel">New Library</h4>
    </div>
        <form:form id="addLibrariesForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/addlibraries" method="post" autocomplete="off" enctype="multipart/form-data">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="libraryname">Library Name</label></td>
                    <td><input id="libraryname" name="libraryname" type="text" /></td>

                </tr>
                <tr>
                    <td><label for="libraryversion">Library Version</label></td>
                    <td><input id="libraryversion" name="libraryversion" type="text" /></td>

                </tr>
                <tr>
                    <td><label for="vendor">Vendor</label></td>
                    <td><input id="vendor" name="vendor" type="text" /></td>

                </tr>
                <tr>
                    <td><label for="license">License</label></td>
                    <td><input id="license" name="license" type="text" /></td>

                </tr>
                <tr>
                    <td><label for="Licensefile">License File</label></td>
                    <td><input id="Licensefile" name="Licensefile" type="file" /></td>

                </tr>

                <tr>
                    <td><label for="language">Language</label></td>
                    <td><input id="language" name="language" type="text" /></td>

                </tr>
                <tr>
                    <td><label for="secuniaID">SecuniaID</label></td>
                    <td><input id="secuniaID" name="secuniaID" type="text" /></td>

                </tr>

            </table>
        </div>

            <div class="modal-footer">
                <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
                <button class="modalSubmit btn btn-primary">Add Library</button>
            </div>

            <tr>
        </form:form>

</div>