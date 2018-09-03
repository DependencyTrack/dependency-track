<%@page import="alpine.Config" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%!
    private static final String BUILD_ID = Config.getInstance().getApplicationBuildUuid();
    private static final String VERSION_PARAM = "?v=" + BUILD_ID;
%>
<script type="text/javascript" src="<c:url value="/assets/jquery/jquery-3.2.1.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/jquery/jquery.storageapi.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/jquery/jquery.easypiechart.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/jquery/typeahead.bundle.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bootstrap/js/bootstrap.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bootstrap-table/bootstrap-table.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bootstrap-table/extensions/flat-json/bootstrap-table-flat-json.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bootstrap-toggle/js/bootstrap-toggle.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bootstrap-tagsinput/bootstrap-tagsinput.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bootstrap-select/js/bootstrap-select.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bootstrap-daterangepicker/moment.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bootstrap-daterangepicker/daterangepicker.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/d3/d3.v3.5.17.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/d3/radar-chart.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/d3/nv.d3.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/js-xss/xss.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/showdown/showdown.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/showdown/showdown-xss-filter.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/bind.min.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/auth.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/rest.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/common.js"/><%=VERSION_PARAM%>"></script>
<script type="text/javascript" src="<c:url value="/assets/chart.js"/><%=VERSION_PARAM%>"></script>
