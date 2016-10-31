

class JRELogger:
    """Clean this up!"""

    def __init__(self, filename="JRELog.txt"):
        self.filename = filename
        self.log = open(filename, 'w')
        self.log.write("#################\n\n")
        self.log.write("JRE Audit Findings\n\n")
    
    def __del__(self):
        self.log.write("#################\n\n")
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
            log.write("Check SV-43621r1_rule\n")
        
