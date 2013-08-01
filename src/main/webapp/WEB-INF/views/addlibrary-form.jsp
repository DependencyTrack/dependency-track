<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<form:form method="post" action="${pageContext.request.contextPath}/addlibrary/${appversionid}">
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
                        <tr>
                            <td></td>
                            <td>
                                <input type="submit" value="Add" />
                                <input type="button" value="Cancel" onclick="window.location='/library/${appversionid}'" />
                            </td>
                        </tr>
                    </table>
                </form:form>