<%--
  ~ Copyright 2013 Axway
  ~
  ~ This file is part of OWASP Dependency-Track.
  ~
  ~ Dependency-Track is free software: you can redistribute it and/or modify it under the terms of the
  ~ GNU General Public License as published by the Free Software Foundation, either version 3 of the
  ~ License, or (at your option) any later version.
  ~
  ~ Dependency-Track is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
  ~ even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
  ~ Public License for more details.
  ~
  ~ You should have received a copy of the GNU General Public License along with Dependency-Track.
  ~ If not, see http://www.gnu.org/licenses/.
  --%>

<p>
    ${properties.shortname} is a web application that allows organizations to document the use of third-party components
    across multiple applications and versions.
</p>

<p>
    The <a href="https://www.owasp.org/index.php/Top_10_2013">OWASP Top Ten 2013</a> introduces, for the first time,
    the use of third-party components with known vulnerabilities. ${properties.shortname} aims to document the usage of
    all components, the vendors, libraries, versions and licenses used and provide visibility into the use of vulnerable
    components.
</p>

<p>
    Additional information can be found on the
    <a href="https://www.owasp.org/index.php/OWASP_Dependency_Track_Project">${properties.longname} Project Page</a>.
</p>

<pre>
    Version:    ${properties.version}
    Build Date: ${properties.builddate}
</pre>