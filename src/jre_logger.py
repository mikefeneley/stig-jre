#!/usr/bin/env python
# -*-coding: utf-8 -*-

DEFAULT_CONFIG = "JRELog.txt"

class JRELogger:
    """JRELogger writes error messages to the JRE log file
    for every rule in the JRE STIG that is violated.
    """

    def __init__(self, filename=DEFAULT_CONFIG):
        self.filename = filename
        self.log = open(filename, 'w')
        self.log.write("#########################\n\n")
        self.log.write("JRE Audit Findings\n\n")
    
    def __del__(self):
        print("Write out")
        self.log.write("#########################\n\n")
        self.log.close()

    def has_deployment_file_errmsg(self, success):
        if not success:
           self.log.write("Check SV-43621r1_rule: ")
           self.log.write("A configuration file must be present to deploy properties for JRE.\n\n")
           self.log.write("To fix: ")
           self.log.write("Create a JRE deployment config file named 'deployment.config' in library directory.\n\n\n")
    
    def has_properties_file_errmsg(self, success):
         if not success:
            self.log.write("Check SV-43620r1_rule: ")
            self.log.write("A properties file must be present to hold all the keys that establish properties within the Java control panel.\n\n")
            self.log.write("To fix: ")
            self.log.write("Create the Java deployment properties file named deployment.properties in the lib directory.\n\n\n")

    def permission_dialog_disabled_errnsg(self, success):
        if not success:
             self.log.write("Check SV-43596r1_rule: ")
             self.log.write("The dialog to enable users to grant permissions to execute signed content from an un-trusted authority must be disabled.\n\n")
             self.log.write("To fix: ")
             self.log.write("Add or update the key 'deployment.security.askgrantdialog.notinca' to be 'false' in the file deployment.properties.\n\n\n")
    
    def permission_dialog_locked_errmsg(self, success):
        if not success:
             self.log.write("Check SV-43601r1_rule: ")
             self.log.write("The dialog enabling users to grant permissions to execute signed content from an un-trusted authority must be locked.\n\n")
             self.log.write("To fix: ")
             self.log.write("Add the key 'deployment.security.askgrantdialog.notinca.locked to the file deployment.properties.\n\n\n")

    def publisher_revocation_enabled_errmsg(self, success):
        if not success:
            self.log.write("Check SV-43604r1_rule: ")
            self.log.write("The dialog to enable users to check publisher certificates for revocation must be enabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Add or update the key 'deployment.security.validation.crl' to be 'true' in the file deployment.properties\n\n\n")

    def publisher_revocation_locked_errmsg(self, success):
        if not success:
            self.log.write("Check SV-43617r1_rule: ")
            self.log.write("The option to enable users to check publisher certificates for revocation must be locked.\n\n")
            self.log.write("To fix: ")
            self.log.write("To fix add the key 'deployment.security.validation.crl.locked in the file deployment.properties\n\n\n")

    def certificate_validation_enabled_errmsg(self, success):
        if not success:
            self.log.write("Check SV-43618r1_rule: ")
            self.log.write("The option to enable online certificate validation must be enabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Add or update the key 'deployment.security.validation.ocsp' to be 'true' in the file deployment.properties\n\n\n")

    def certificate_validation_locked_errmsg(self, success):
        if not success:
            self.log.write("Check SV-43619r1_rule: ")
            self.log.write("The option to enable online certificate validation must be locked.\n\n")
            self.log.write("To fix: ")
            self.log.write("Add the key 'deployment.security.validation.ocsp.locked' in the file deployment.properties\n\n\n")

    def config_keys_set_errmsg(self, success):
        if not success:
            self.log.write("Check SV-43649r1_rule:")
            self.log.write("The configuration file must contain proper keys and values to deploy settings correctly.\n\n")
            self.log.write("To fix: ")
            self.log.write("Include the following keys in the configuration file: 'deployment.system.config=file:/usr/Java/jre/lib/deployment.properties' and 'deployment.system.config.mandatory=false'.\n\n\n")

    def check_jre_version_errmsg(self, success):
        if not success:
            self.log.write("Check SSV-51133r1_rule: ")
            self.log.write("The version of the JRE running on the system must be the most current available.\n\n")
            self.log.write("To fix: ")
            self.log.write("Install latest version of Java JRE.\n\n\n")

    def check_no_outdated_errmsg(self, success):
        if not success:
            self.log.write("Check SV-75505r2_rule: ")
            self.log.write("Java Runtime Environment (JRE) versions that are no longer supported by the vendor for security updates must not be installed on a system.\n\n")
            self.log.write("To fix: ")
            self.log.write("Upgrade Java Runtime Environment for Unix software to a supported version.\n\n\n")
