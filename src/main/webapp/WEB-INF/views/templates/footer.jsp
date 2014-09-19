<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

    <div class="footer">
        <div class="identifier"><e:forHtmlContent value="${properties.longname}"/> v<e:forHtmlContent value="${properties.version}"/></div>
    </div>