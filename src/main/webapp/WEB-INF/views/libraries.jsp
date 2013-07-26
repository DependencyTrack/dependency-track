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
                <th>&nbsp;</th>

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
                    <td style="vertical-align:top;text-align:right;">
                        <div class="btn-group">
                            <a data-toggle="modal"
                               data-libraryid ="${libList.library.id}"
                               data-vendorid ="${libList.library.libraryVendor.id}"
                               data-licenseid ="${libList.library.license.id}"
                               data-libraryversionid ="${libList.id}"


                               data-vendor ="${libList.library.libraryVendor.vendor}"
                               data-libraryname ="${libList.library.libraryname}"
                               data-libraryversion ="${libList.libraryversion}"
                               data-licensename ="${libList.library.license.licensename}"
                               data-language ="${libList.library.language}"
                               data-secunia ="${libList.library.secunia}"
                               class="open-EditLibrariesModal btn" href="#editLibrariesModal">Edit</a>
                        </div>
                    </td>
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

   <%--editting libraries without being associated to applications--%>

<div id="editLibrariesModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="editApplicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="editLibrariesModalLabel">Edit Library
            <span class="delete-span">
				<a class="btn btn-danger header-button" id="deleteLibrary" href="" onclick="return confirm('Possibly Deleting a library bound to multiple application.Are you sure you want to delete the application?')">Delete</a>
			</span>
        </h4>
    </div>
    <form:form id="editLibrariesForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/updatelibrary" method="post" autocomplete="off" enctype="multipart/form-data">
        <div class="modal-body">
                <table>
                    <tr>
                        <td><label for="libraryname">Library Name</label></td>
                        <td><input id="librarynameedit" name="libraryname" type="text" value=""/></td>

                    </tr>
                    <tr>
                        <td><label for="libraryversion">Library Version</label></td>
                        <td><input id="libraryversionedit" name="libraryversion" type="text" value=""/></td>

                    </tr>
                    <tr>
                        <td><label for="vendor">Vendor</label></td>
                        <td><input id="vendoredit" name="vendor" type="text" value=""/></td>

                    </tr>
                    <tr>
                        <td><label for="license">License</label></td>
                        <td><input id="licenseedit" name="license" type="text" value=""/></td>

                    </tr>
                    <tr>
                        <td><label for="Licensefile">License File</label></td>
                        <td><input id="Licensefileedit" name="Licensefile" type="file" /></td>

                    </tr>

                    <tr>
                        <td><label for="language">Language</label></td>
                        <td><input id="languageedit" name="language" type="text" value=""/></td>

                    </tr>
                    <tr>
                        <td><label for="secuniaID">SecuniaID</label></td>
                        <td><input id="secuniaIDedit" name="secuniaID" type="text" value=""/></td>

                    </tr>

                </table>
                    <%--<input type="hidden" id="addid" name="id" value=""/>--%>
                <input type="hidden" id="editvendorid" name="editvendorid" value=""/>
                <input type="hidden" id="editlicenseid" name="editlicenseid" value=""/>
                <input type="hidden" id="editlibraryid" name="editlibraryid" value=""/>
                <input type="hidden" id="editlibraryversionid" name="editlibraryversionid" value=""/>
            </div>



        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Save Changes</button>
        </div>
    </form:form>
</div>

