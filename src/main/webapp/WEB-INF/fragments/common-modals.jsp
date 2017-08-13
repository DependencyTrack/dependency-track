<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<div class="modal fade" id="modalAbout" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title">About</h4>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-sm-6 col-md-6">
                        <img src="<c:url value="/images/dc.svg"/>" style="width:200px; margin-bottom:20px">
                        <p>
                            Dependency-Check is a utility that identifies project dependencies and checks if there
                            are any known, publicly disclosed vulnerabilities.
                        </p>
                        <p>
                            <span id="dcAppName"></span> v<strong id="dcAppVersion"></strong>
                        </p>
                        <p>
                            Dependency-Check is Copyright &copy; Jeremy Long. All Rights Reserved.
                        </p>
                    </div>
                    <div class="col-sm-6 col-md-6">
                        <img src="<c:url value="/images/dt.svg"/>" style="width:200px; margin-bottom:20px">
                        <p>
                            Dependency-Track is an component management system that proactively identifies
                            vulnerabilities over time, and across applications.
                        </p>
                        <p>
                            <span id="systemAppName"></span> v<strong id="systemAppVersion"></strong> (built on: <span id="systemAppTimestamp"></span>)
                        </p>
                        <p>
                            Dependency-Track is Copyright &copy; Steve Springett. All Rights Reserved.
                        </p>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<div class="modal" id="modal-login" tabindex="-1" role="dialog" data-backdrop="static" aria-labelledby="modal-login-label" aria-hidden="true">
    <div class="vertical-alignment-helper">
        <div class="modal-dialog vertical-align-center">
            <div class="modal-content login-modal-content">
                <div class="modal-header login-modal-header login-header">
                    <img src="<c:url value="/images/dt.svg"/>" style="width:200px"/>
                </div>
                <div class="modal-body login-modal-body">
                    <form id="login-form" role="form" action="" method="post" class="login-form" autocomplete="off">
                        <div class="form-group">
                            <label class="sr-only" for="username">Username</label>
                            <input type="text" name="username" placeholder="Username..." class="form-control" id="username">
                        </div>
                        <div class="form-group">
                            <label class="sr-only" for="password">Password</label>
                            <input type="password" name="password" placeholder="Password..." class="form-control" id="password">
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">Log In</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

