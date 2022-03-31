# Dependency-Track-Global-Suppression-Utility
<i><b>A utility script for Dependency Track.</i></b><br><br>
This script will suppress (or unsuppress) a vulnerability across all projects at once.<br><br>
All you need to start is to provide:
<ul>
<li>The Dependency Track Base URL.</li>
<li>The Dependency Track API Key.</li>
<liThe PURL of the package you would like to suppress/unsuppress.</li>
<li>The vulnerabilities UUID.</li>
<li>The suppression status. (If you want to suppress or unsuppress)</li>
</ul>
You can also provide a <b>comment</b> and <b>analysisState</b> in the <b>globallySuppressVulnerability()</b> method.
<br><br><i>This was tested working on Dependency-Track v4.3.6.</i></b>
