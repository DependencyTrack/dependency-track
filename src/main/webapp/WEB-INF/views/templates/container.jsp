<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<div class="content-outer-container">
    <div class="content-inner-container">
        <div class="title-container">
            <div class="title">${param.title}</div>
            <div class="title-buttons">${param.buttons}</div>
        </div>
        <div class="content">
            <jsp:include page="/WEB-INF/views/${param.content}.jsp"/>
        </div>
    </div>
</div>