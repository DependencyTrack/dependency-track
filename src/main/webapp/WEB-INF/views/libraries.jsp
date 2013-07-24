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