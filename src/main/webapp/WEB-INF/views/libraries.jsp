<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

<spring:message code="permissions.uploadlicense" var="uploadlicense"/>
<spring:message code="permissions.updatelibrary" var="updatelibrary"/>

<div id="librariesContainer">
    <c:if test="${!empty libList}">
        <table class="list tablesorter">
            <thead>
            <tr>
                <th><spring:message code="label.vendor"/></th>
                <th><spring:message code="label.name"/></th>
                <th><spring:message code="label.version"/></th>
                <th><spring:message code="label.license"/></th>
                <th><spring:message code="label.language"/></th>
                <shiro:hasPermission name="${updatelibrary}">
                <th>&nbsp;</th>
                    </shiro:hasPermission>
            </tr>
            </thead>
            <tbody>
            <c:forEach items="${libList}" var="libList">
                <tr>
                    <td><e:forHtmlContent value="${libList.library.libraryVendor.vendor}"/></td>
                    <td><e:forHtmlContent value="${libList.library.libraryname}"/></td>
                    <td><e:forHtmlContent value="${libList.libraryversion}"/></td>
                    <td><a data-toggle="modal" class="open-LicenseLibrariesModal" data-licensefiletype ="${libList.library.license.contenttype}" data-licenseid ="${libList.library.license.id}" data-licensename ="${e:forHtmlAttribute(libList.library.license.licensename)}" data-licensfileename ="${libList.library.license.filename}" href="#licenseLibrariesModal"><e:forHtmlContent value="${libList.library.license.licensename}"/></a></td>
                    <td><e:forHtmlContent value="${libList.library.language}"/></td>
                    <shiro:hasPermission name="${updatelibrary}">
                    <td style="vertical-align:top;text-align:right;">
                        <div class="btn-group">
                            <a data-toggle="modal"
                               data-libraryid ="${libList.library.id}"
                               data-vendorid ="${libList.library.libraryVendor.id}"
                               data-licenseid ="${libList.library.license.id}"
                               data-libraryversionid ="${libList.id}"
                               data-vendor ="${e:forHtmlAttribute(libList.library.libraryVendor.vendor)}"
                               data-libraryname ="${e:forHtmlAttribute(libList.library.libraryname)}"
                               data-libraryversion ="${e:forHtmlAttribute(libList.libraryversion)}"
                               data-licensename ="${e:forHtmlAttribute(libList.library.license.licensename)}"
                               data-language ="${e:forHtmlAttribute(libList.library.language)}"
                               class="open-EditLibrariesModal btn" href="#editLibrariesModal">Edit</a>
                        </div>
                    </td>
                        </shiro:hasPermission>
                </tr>
            </c:forEach>
            </tbody>
        </table>
    </c:if>
</div>

<div id="libraryModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="applicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="applicationModalLabel"><spring:message code="label.library.new"/></h4>
    </div>

        <c:url value="/addlibraries" var="addlibrariesUrl"/>
        <form:form id="addLibrariesForm" style="margin-bottom:0" action="${addlibrariesUrl}" method="post" autocomplete="off" enctype="multipart/form-data">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="vendor"><spring:message code="label.vendor"/></label></td>
                    <td>
                        <div style="display:inline">
                            <select id="vendorid" name="libraryname" class="vendoridclass" >
                                <option value="">--</option>
                            </select>
                            <input id="vendor" name ="vendorsel" type="text" required="required" style="position:relative; height: 20px; border: 0; left: -223px; width: 183px;" />
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><label for="libraryname"><spring:message code="label.name"/></label></td>
                    <td>
                        <div style="display:inline">
                        <select id="librarynameid" name="libraryname" autofocus="autofocus" class="librarynameidclass" >
                            <option value="">--</option>
                        </select>
                        <input id="libraryname" name ="libnamesel" type="text" required="required" style="  position:relative; height: 20px; border: 0; left: -223px; width: 183px;" />
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><label for="libraryversion"><spring:message code="label.version"/></label></td>
                    <td>
                        <div style="display:inline">
                        <select id="libraryversionid" name="libraryname" class="libraryversionidclass">
                            <option value="">--</option>
                        </select>
                        <input id="libraryversion" name ="libversel" type="text"  required="required" style="  position:relative; height: 20px; border: 0; left: -223px; width: 183px;" />
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><label for="license"><spring:message code="label.license"/></label></td>
                    <td>
                        <div style="display:inline">
                            <c:if test="${!empty uniquelicList}">
                        <select id="licenseids" name="license"  class="licenseidsclass">
                            <option value="">--</option>
                            <c:forEach items="${uniquelicList}" var="libList">
                                <option value="${e:forHtmlAttribute(libList.licensename)}"><e:forHtmlContent value="${libList.licensename}"/></option>
                            </c:forEach>
                        </select>
                            </c:if>
                        <input id="license" name ="licensesel" class="licenselosefocus" type="text" required="required" style="  position:relative; height: 20px; border: 0; left: -223px; width: 183px;" />
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><label id="Licensefilelabel" for="Licensefile"><spring:message code="label.license.file" /></label></td>
                    <td><input id="Licensefile" name="Licensefile" type="file" /></td>
                </tr>
                <tr>
                    <td><label for="language"><spring:message code="label.language"/></label></td>
                    <td>
                        <div style="display:inline">
                        <select id="languageid" name="language"  class="languageidclass">
                            <option value="">--</option>
                            <c:forEach items="${uniqueLang}" var="libList">
                                <option value="${e:forHtmlAttribute(libList)}"><e:forHtmlContent value="${libList}"/></option>
                            </c:forEach>
                        </select>
                        <input id="language" name ="languagesel"  type="text" required="required" style="  position:relative; height: 20px; border: 0; left: -223px; width: 183px;" />
                        </div>
                    </td>
                </tr>
            </table>
        </div>

        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.library.add"/></button>
        </div>
        </form:form>
    </div>

   <%--editting libraries without being associated to applications--%>

<div id="editLibrariesModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="editLibrariesModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="editLibrariesModalLabel"><spring:message code="label.library.edit"/>
            <span class="delete-span">
                <spring:message code="confirm.delete.library" var="confirmDeleteLibrary"/>
				<a class="btn btn-danger header-button" id="deleteLibrary" href="" onclick="return confirm('${confirmDeleteLibrary}')"><spring:message code="label.delete"/></a>
			</span>
        </h4>
    </div>

    <c:url value="/updatelibrary" var="updatelibraryUrl"/>
    <form:form id="editLibrariesForm" style="margin-bottom:0" action="${updatelibraryUrl}" method="post" autocomplete="off" enctype="multipart/form-data">
        <div class="modal-body">
                <table>
                    <tr>
                        <td><label for="vendoredit"><spring:message code="label.vendor"/></label></td>
                        <td><input id="vendoredit" name="vendor" type="text" value=""/></td>
                    </tr>
                    <tr>
                        <td><label for="librarynameedit"><spring:message code="label.name"/></label></td>
                        <td><input id="librarynameedit" name="libraryname" type="text" value=""/></td>
                    </tr>
                    <tr>
                        <td><label for="libraryversionedit"><spring:message code="label.version"/></label></td>
                        <td><input id="libraryversionedit" name="libraryversion" type="text" value=""/></td>
                    </tr>

                    <tr>
                        <td><label for="licenseeditids"><spring:message code="label.license"/></label></td>
                        <td>
                            <div style="display:inline">
                                <select id="licenseeditids" name="license">
                                    <option value="">--</option>
                                    <c:forEach items="${uniquelicList}" var="libList">
                                        <option value="${e:forHtmlAttribute(libList.licensename)}"><e:forHtmlContent value="${libList.licensename}"/></option>
                                    </c:forEach>
                                </select>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td><label for="languageedit"><spring:message code="label.language"/></label></td>
                        <td><input id="languageedit" name="language" type="text" value=""/></td>
                    </tr>
                </table>
                <input type="hidden" id="editvendorid" name="editvendorid" value=""/>
                <input type="hidden" id="editlicenseid" name="editlicenseid" value=""/>
                <input type="hidden" id="editlibraryid" name="editlibraryid" value=""/>
                <input type="hidden" id="editlibraryversionid" name="editlibraryversionid" value=""/>
            </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.saveChanges"/></button>
        </div>
    </form:form>
</div>

<div id="licenseLibrariesModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="licenseLibrariesModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="licenseLibrariesModalLabel"><spring:message code="label.license.view"/></h4>
    </div>

    <c:url value="/downloadlicense" var="downloadlicenseUrl"/>
    <form:form id="licenseLibrariesForm" style="margin-bottom:0" action="${downloadlicenseUrl}" method="post" autocomplete="off" enctype="multipart/form-data">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="licensename"><spring:message code="label.name"/></label></td>
                    <td><input id="licensename" name="licensename" type="text" value="" readonly/></td>
                </tr>
                <tr>
                    <td><label for="licensfileename"><spring:message code="label.license.file"/></label></td>
                    <td><input id="licensfileename" name="licensfileename" type="text" value="" readonly/></td>
                </tr>
            </table>
            <iframe id="viewlicense" width="100%" height="400" src="" seamless="seamless" sandbox="allow-same-origin"></iframe>
            <input type="hidden" id="licenseid" name="licenseid" value=""/>

        </div>



        <div class="modal-footer">

            <button class="btn" data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <shiro:hasPermission name="${uploadlicense}">
            <a data-toggle="modal" class="open-licenseFileUploadModalButton btn btn-primary" data-dismiss="modal" href="#licenseFileUploadModal" ><spring:message code="label.upload"/></a>
            </shiro:hasPermission>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.download"/></button>

        </div>
    </form:form>
</div>

<div id="licenseFileUploadModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="licenseFileUploadModal" aria-hidden="true">
    <div class="modal-header">
        <h4 id="licenseFileUploadModalLabel"><spring:message code="label.license.upload"/></h4>
    </div>

    <c:url value="/uploadlicense" var="uploadlicenseUrl"/>
    <form:form id="uploadLicenseFileForm" style="margin-bottom:0" action="${uploadlicenseUrl}" method="post" autocomplete="off" enctype="multipart/form-data">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="editlicensename"><spring:message code="label.name"/></label></td>
                    <td><input id="editlicensename" name="editlicensename" type="text" value="" /></td>
                </tr>
                <tr>
                    <td><label for="uploadlicensefile"><spring:message code="label.license.file" /></label></td>
                    <td><input id="uploadlicensefile" name="uploadlicensefile" type="file" value="" /></td>
                </tr>
                <input type="hidden" id="uploadlicenseid" name="uploadlicenseid" value=""/>
            </table>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true"><spring:message code="label.close"/></button>
            <button class="modalSubmit btn btn-primary"><spring:message code="label.upload"/></button>
        </div>
    </form:form>
</div>