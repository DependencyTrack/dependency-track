<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<div class="modal fade" id="modal-snapshotNotification" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-md" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <span class="modal-title">Snapshot Notification</span>
            </div>
            <div class="modal-body">
                <p>
                    This version of Dependency-Track is a snapshot release that is dynamically
                    generated from continuous integration or from manually compiling from a branch.
                    It is likely beta-quality software and has not undergone extensive testing.
                    It may contain defects and incomplete features and functionality.
                </p>
                <p>
                    Links to production-quality releases can be found at
                    <a href="https://dependencytrack.org/">https://dependencytrack.org/</a>
                </p>
                <p>
                    Please consider contributing feedback and pull requests to help improve
                    Dependency-Track. All contributions are appreciated.
                    <a href="https://github.com/DependencyTrack/dependency-track">https://github.com/DependencyTrack/dependency-track</a>
                </p>
                <p><strong>Do not use snapshot releases on production data.</strong></p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="modal-about" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <span class="modal-title">About</span>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-sm-6 col-md-6">
                        <a href="https://dependencytrack.org/">
                            <img src="<c:url value="/images/dt.svg"/>" style="width:200px; margin-bottom:20px">
                        </a>
                        <p>
                            Dependency-Track is an intelligent Software Composition Analysis (SCA) platform
                            that allows organizations to identify and reduce risk from the use of third-party
                            and open source components.
                        </p>
                        <p>
                            <span id="systemAppName"></span> v<span id="systemAppVersion"></span>
                        </p>
                        <p>
                            Build ID: <span id="systemAppBuildId"></span>
                        </p>
                    </div>
                    <div class="col-sm-6 col-md-6">
                        <a href="https://github.com/stevespringett/Alpine">
                            <img src="<c:url value="/images/Alpine.svg"/>" style="width:200px; margin-bottom:20px">
                        </a>
                        <p>
                            Alpine is an opinionated scaffolding framework that jump-starts Java projects with
                            an API-first design, secure defaults, and minimal dependencies to aid in the creation
                            of performant, thin-server applications.
                        </p>
                        <p>
                            <span id="systemFrameworkName"></span> v<span id="systemFrameworkVersion"></span>
                        </p>
                        <p>
                            Build ID: <span id="systemFrameworkBuildId"></span>
                        </p>
                    </div>
                </div>
                <div class="row" style="border-bottom: 1px solid #e5e5e5; margin: 10px 0 10px 0; padding: 0;"></div>
                <div class="row">
                    <div class="col-sm-6 col-md-6">
                        <h4>Community Resources</h4>
                        <ul class="fa-ul">
                            <li><i class="fa-li fa fa-link" aria-hidden="true"></i><a href="https://dependencytrack.org/">Website</a></li>
                            <li><i class="fa-li fa fa-book" aria-hidden="true"></i><a href="https://docs.dependencytrack.org/">Documentation</a></li>
                            <li><i class="fa-li fa fa-github" aria-hidden="true"></i><a href="https://github.com/DependencyTrack">GitHub</a></li>
                            <li><i class="fa-li fa fa-slack" aria-hidden="true"></i><a href="https://owasp.slack.com/messages/proj-dependency-track">Slack</a> (<a href="https://owasp.herokuapp.com/">invite</a>)</li>
                            <li><i class="fa-li fa fa-twitter" aria-hidden="true"></i><a href="https://twitter.com/dependencytrack">Twitter</a></li>
                            <li><i class="fa-li fa fa-youtube-play" aria-hidden="true"></i><a href="https://www.youtube.com/channel/UC8xdttysl3gNAQYvk1J9Efg">YouTube</a></li>
                        </ul>
                    </div>
                    <div class="col-sm-6 col-md-6">
                        <h4>Datasource Providers</h4>
                        <ul class="fa-ul">
                            <li><i class="fa-li fa fa-link" aria-hidden="true"></i><a href="https://nvd.nist.gov/">National Vulnerability Database</a></li>
                            <li><i class="fa-li fa fa-link" aria-hidden="true"></i><a href="https://nodesecurity.io/">Node Security Platform</a></li>
                            <li><i class="fa-li fa fa-link" aria-hidden="true"></i><a href="https://ossindex.sonatype.org/">Sonatype OSS Index</a></li>
                            <li><i class="fa-li fa fa-link" aria-hidden="true"></i><a href="https://vulndb.cyberriskanalytics.com">VulnDB</a> (Optional)</li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <div style="text-align:center;margin-bottom:-25px;">Copyright &copy; Steve Springett. All Rights Reserved.</div>
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

<div class="modal" id="modal-forcePasswordChange" tabindex="-1" role="dialog" data-backdrop="static" aria-labelledby="modal-forcePasswordChange-label" aria-hidden="true">
    <div class="vertical-alignment-helper">
        <div class="modal-dialog vertical-align-center">
            <div class="modal-content login-modal-content">
                <div class="modal-header login-modal-header login-header">
                    <img src="<c:url value="/images/dt.svg"/>" style="width:200px"/>
                </div>
                <div class="modal-body login-modal-body">
                    <form id="forcePasswordChange-form" role="form" action="" method="post" class="login-form" autocomplete="off">
                        <h4>Password change required</h4>
                        <div class="form-group">
                            <label class="sr-only" for="username">Username</label>
                            <input type="text" placeholder="Username..." class="form-control" id="forcePasswordChange-username">
                        </div>
                        <div class="form-group">
                            <label class="sr-only" for="forcePasswordChange-password">Current Password</label>
                            <input type="password" placeholder="Current Password..." class="form-control" id="forcePasswordChange-password">
                        </div>
                        <div class="form-group">
                            <label class="sr-only" for="forcePasswordChange-newPassword">New Password</label>
                            <input type="password" placeholder="New Password..." class="form-control" id="forcePasswordChange-newPassword">
                        </div>
                        <div class="form-group">
                            <label class="sr-only" for="forcePasswordChange-confirmPassword">Confirm New Password</label>
                            <input type="password" placeholder="Confirm New Password..." class="form-control" id="forcePasswordChange-confirmPassword">
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">Change Password</button>
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
                <span class="modal-title">Profile</span>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label for="profileUsernameInput">Username</label>
                    <input type="text" name="username" class="form-control" id="profileUsernameInput" disabled="disabled">
                </div>
                <div class="form-group">
                    <label class="required" for="profileFullnameInput">Full Name</label>
                    <input type="text" name="fullname" class="form-control required" id="profileFullnameInput">
                </div>
                <div class="form-group">
                    <label class="required" for="profileEmailInput">Email</label>
                    <input type="text" name="email" class="form-control required" id="profileEmailInput">
                </div>
                <div class="form-group">
                    <label for="profileNewPasswordInput">New Password</label>
                    <input type="password" name="newPassword" class="form-control" id="profileNewPasswordInput">
                </div>
                <div class="form-group">
                    <label for="profileConfirmPasswordInput">Confirm Password</label>
                    <input type="password" name="confirmPassword" class="form-control" id="profileConfirmPasswordInput">
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal" id="updateProfileButton">Update</button>
                <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="modal-genericError" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-md" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <span class="modal-title">Error</span>
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
                <span class="modal-title">Information</span>
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
