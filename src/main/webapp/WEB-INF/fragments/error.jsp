<%@page contentType="application/json; charset=UTF-8" pageEncoding="UTF-8" isErrorPage="true"%>
<%
// String errorMessage = exception.getMessage();
response.setStatus(500);
%>
{
    "message": "An error occurred. Please try again."
}