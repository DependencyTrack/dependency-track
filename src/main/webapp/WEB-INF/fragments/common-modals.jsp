<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<div class="modal fade" id="modal-about" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title">About</h4>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-sm-6 col-md-6">
                        <a href="https://www.owasp.org/index.php/OWASP_Dependency_Track_Project">
                            <img src="<c:url value="/images/dt.svg"/>" style="width:200px; margin-bottom:20px">
                        </a>
                        <p>
                            Dependency-Track is a Software Composition Analysis (SCA) platform that allows
                            organizations to automatically ingest and identify third-party components and any
                            inherited vulnerabilities from their use.
                        </p>
                        <p>
                            <span id="systemAppName"></span> v<span id="systemAppVersion"></span>
                        </p>
                        <p>
                            Copyright &copy; Steve Springett. All Rights Reserved.
                        </p>
                    </div>
                    <div class="col-sm-6 col-md-6">
                        <a href="https://www.owasp.org/index.php/OWASP_Dependency_Check">
                            <img src="<c:url value="/images/dc.svg"/>" style="width:200px; margin-bottom:20px">
                        </a>
                        <p>
                            Dependency-Check is a Software Composition Analysis (SCA) utility that uses
                            evidence-based analysis to identify project dependencies and determines if they contain
                            publicly disclosed vulnerabilities.
                        <p>
                            <span id="dcAppName"></span> v<span id="dcAppVersion"></span>
                        </p>
                        <p>
                            Copyright &copy; Jeremy Long. All Rights Reserved.
                        </p>
                    </div>
                </div>
                <div class="row" style="border-bottom: 1px solid #e5e5e5; margin: 10px 0 10px 0; padding: 0;">
                    <h4>Credits</h4>
                </div>
                <div class="row">
                    <div class="col-sm-6 col-md-6">
                        <a href="https://github.com/stevespringett/Alpine">
                            <img src="<c:url value="/images/Alpine.svg"/>" style="width:200px; margin-bottom:20px">
                        </a>
                        <p>
                            An opinionated scaffolding library that jump-starts Java projects with an API-first
                            design, secure defaults, and minimal dependencies.
                        </p>
                    </div>
                    <div class="col-sm-6 col-md-6">
                        <h4>Datasource providers</h4>
                        <ul>
                            <li><a href="https://nvd.nist.gov/">National Vulnerability Database</a></li>
                            <li><a href="https://nodesecurity.io/">Node Security Platform</a></li>
                            <li><a href="https://vulndb.cyberriskanalytics.com">VulnDB</a> (Optional)</li>
                        </ul>
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

<div class="modal fade" id="modal-profile" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-md" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title">Profile</h4>
            </div>
            <div class="modal-body">
                <h3>MOCKUP: Not yet working</h3>
                <div class="form-group">
                    <label class="sr-only" for="profileNameInput">Name</label>
                    <input type="text" name="name" required="true" placeholder="Name..." class="form-control" id="profileNameInput">
                </div>
                <div class="form-group">
                    <label class="sr-only" for="profileEmailInput">Email</label>
                    <input type="text" name="email" required="true" placeholder="Email..." class="form-control" id="profileEmailInput">
                </div>
                <div class="form-group">
                    <label class="sr-only" for="profilePasswordInput">Password</label>
                    <input type="password" name="password" required="true" placeholder="Password..." class="form-control" id="profilePasswordInput">
                </div>
                <div class="form-group">
                    <label class="sr-only" for="profileConfirmPasswordInput">Confirm Password</label>
                    <input type="password" name="password" required="true" placeholder="Confirm Password..." class="form-control" id="profileConfirmPasswordInput">
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Update</button>
                <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="modal-genericError" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-md" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title">Error</h4>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-sm-12 col-md-12">
                        <div class="pull-left" style="width:70px; min-width:70px; max-width:70px;">
                            <i class="fa fa-exclamation-triangle fa-4x" aria-hidden="true"></i>
                        </div>
                        <div>
                            <p id="modal-genericErrorContent"></p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="modal-informational" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-md" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title">Information</h4>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-sm-12 col-md-12">
                        <div class="pull-left" style="width:70px; min-width:70px; max-width:70px;">
                            <i class="fa fa-info-circle fa-4x" aria-hidden="true"></i>
                        </div>
                        <div>
                            <p id="modal-infoMessage"></p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>
