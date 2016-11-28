# stig-jre
<b>Update 11/13/2016:</b>

STIG-JRE was originally intended to be a vulnerability checker that checked windows configuration against the recommendations of the STIG guides provided by the DISA. STIG-JRE uses Python implementations of each individual STIG guide to check against the STIG requirements.

According to the NISA, the best way to implement a SCAP, (Security Content Automation Protocol), like STIG-JRE is to use OVAL, (Open Vulnerability and Assessment Language) repository to check the vulnerabilities provided by an XCCDF, (Extensible Configuration Checklist Description Format) and report the misconfigurations back the user.

Because the approach used to start this project is outdated and the correct approach is already implemented here: https://github.com/OpenSCAP, I am no longer going to continue regular work on this project. I may continue to write new methods in my free time in order to learn about STIG requirements, but it is no longer a personal priority.

If you are interested in working on this project with me, I may be interested if you can provide a good reason to do. If so, please contact me here: mfeneley@vt.edu.

<b>Update 11/26/2016:</b>

Initially this tool was originally intended to just check and report misconfiguations back to the user. However, adding the option to change or add configurations to make the system STIG compliant might help this tool stand out from many of the other STIG tools avaliable.

I am still going to work on extending the number of findings that are supported by the STIG Kit, but I also intend to add configuration change functitonality to the program.

<b>#################################################################</b>

<b>Introduction</b>

This tool checks to make sure that the java runtime environment (JRE) installed on your operating system
adheres to the requirements of the DIA STIG.

This program currntly checks all the requirements on the STIG except for the requirement that the most
recent version of the JRE be installed and that no old, unsupported versions of the JRE are installed on the computer.

The JRE STIG requriements for Nix Systems can be seen here:
https://www.stigviewer.com/stig/java_runtime_environment_jre_7_unix/

The list of rules checked with their corresponding finding id in case of a violation is listed below.

Rule, Finding_ID

SV-43621r1_rule, V-32901

SV-43620r1_rule, V-32902

SV-43596r1_rule, V-32828  

SV-43601r1_rule, V-32829

SV-43604r1_rule, V-32830

SV-43617r1_rule, V-32831

SV-43618r1_rule, V-32832

SV-43619r1_rule, V-32833

SV-43649r1_rule, V-32842

SV-51133r1_rule, V-39239

SV-75505r2_rule, V-61037

<b>Using the Program</b>

The program can be run using the command line. Navigate to the src folder after downloading and execute program with the following command:

<i>python jre_auditor.py</i>
