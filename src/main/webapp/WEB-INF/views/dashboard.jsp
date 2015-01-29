<%@taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

<div id="dashboard_canvas_container" style="width:100%">

    <canvas id="dashboard_chart" height="400" width="100"></canvas>
    <script type="text/javascript" src="<c:url value="/resources/dashboard.chart.js"/>"></script>

</div>
