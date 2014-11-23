<%@page language="java" contentType="application/json; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.atg.com/taglibs/json" prefix="json" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<c:set var="atg.taglib.json.prettyPrint" value="${true}" scope="application"/>

<json:object>
    <json:array name="vendors" var="vendor" items="${libraryVendors}">
        <json:object>
            <json:property name="id" value="${vendor.id}"/>
            <json:property name="vendor" value="${vendor.vendor}"/>


            <json:array name="libraries" var="library" items="${vendor.libraries}">
                <json:object>
                    <json:property name="libid" value="${library.id}"/>
                    <json:property name="libname" value="${library.libraryname}"/>
                    <json:property name="liblang" value="${library.language}"/>
                    <json:property name="licname" value="${library.license.licensename}"/>

                    <json:array name="versions" var="version" items="${library.versions}">
                        <json:object>
                            <json:property name="libverid" value="${version.id}"/>
                            <json:property name="libver" value="${version.libraryversion}"/>
                        </json:object>
                    </json:array>



                </json:object>
            </json:array>

        </json:object>
    </json:array>
</json:object>