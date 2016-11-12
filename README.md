# stig-jre

This tool checks to make sure that the java runtime environment (JRE) installed on your operating system
adheres to the requirements of the DIA STIG.

This program currntly checks all the requirements on the STIG except for the requirement that the most
recent version of the JRE be installed and that no old, unsupported versions of the JRE are installed on the computer.

The JRE STIG requriements for Windows 7 can be seen here:
https://www.stigviewer.com/stig/java_runtime_environment_jre_version_7_windows_7/

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

