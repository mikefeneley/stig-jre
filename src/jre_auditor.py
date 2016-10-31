

import os
from subprocess import call
from jre_logger import JRELogger

DEPLOYMENT_FILENAME = "deployment.config"
PROPERTIES_FILENAME = "deployment.properties"
HOLDER_FILE = "hold.txt"
HOLDER_DIR = "./hold.txt"


class JREAuditor:

    def __init__(self):
        self.deployment_file = None
        self.properties_file = None
        self.deployment_path = None
        self.properties_path = None
        self.get_deployment_path()
        self.get_properties_path()
        self.logger = JRELogger()

    def audit_jre(self):
        self.has_deployment_file()
        self.has_properties_file()

        success = self.permission_dialog_disabled()
        self.logger.has_deployment_file_errmsg(success)
        success = self.permission_dialog_locked()
        self.logger.permission_dialog_locked_errmsg(success)
        success = self.publisher_revocation_enabled()
        self.logger.publisher_revocation_enabled_errmsg(success)
        success = self.publisher_revocation_locked()
        self.logger.publisher_revocation_locked_errmsg(success)
        success = self.certificate_validation_enabled()
        self.logger.certificate_validation_enabled_errmsg(success)
        success = self.certificate_validation_locked()
        self.logger.certificate_validation_locked_errmsg(success)
        success = self.config_keys_set()
        del self.logger
        

    def get_deployment_path(self):
        holder = open(HOLDER_FILE, 'w')
        call(["find", "/usr", "-name", DEPLOYMENT_FILENAME], stdout=holder)
        holder.close()
        holder = open(HOLDER_FILE, 'r')


        if(os.path.getsize(HOLDER_DIR) == 0):
            self.deployment_path = None
            call(["rm", HOLDER_FILE])
            return 0

        for file in holder:
            if(line != ''):
                self.deployment_path = line
                holder.close()
                call(["rm", HOLDER_FILE])

                return 1
            else:
                self.deployment_path = None
                holder.close()
                call(["rm", HOLDER_FILE])
                return 0

    def get_properties_path(self):
        holder = open(HOLDER_FILE, 'w')
        call(["find", "/usr", "-name", PROPERTIES_FILENAME], stdout=holder)
        holder.close()
        holder = open(HOLDER_FILE, 'r')

        if(os.path.getsize(HOLDER_DIR) == 0):
            self.deployment_path = None
            call(["rm", HOLDER_FILE])
            return 0

        for file in holder:
            if(line != ''):
                self.deployment_path = line
                holder.close()
                call(["rm", HOLDER_FILE])
                return 1
            else:
                self.deployment_path = None
                holder.close()
                call(["rm", HOLDER_FILE])
                return 0

    def has_deployment_file(self):
        """Check SV-43621r1_rule: A configuration file must be 
        present to deploy properties for JRE.

        Finding ID: V-32901     
        """
        if(self.deployment_path == None):
             return False
        else:
             return True

    def has_properties_file(self):
        """Check SV-43620r1_rule: A properties file must be present to 
        hold all the keys that establish properties within the Java 
        control panel.

        Finding ID: V-32902      
        """
        if(self.properties_path == None):
            return False
        else:
            return True


    def permission_dialog_disabled(self):
        """Check SV-43596r1_rule: The dialog to enable users to grant 
        permissions to execute signed content from an un-trusted 
        authority must be disabled.

        Finding ID: V-32828     
        """
        if(self.properties_path == None):
            return False

        config = open(self.properties_path, 'r')

        locked = False
        for line in config_file:
            if 'deployment.security.askgrantdialog.notinca=false' in line:
                locked = True
        config.close()
        return locked


    def permission_dialog_locked(self):
        """Check SV-43601r1_rule: The dialog to enable users to grant 
        permissions to execute signed content from an un-trusted 
        authority must be disabled.

        Finding ID: V-32829
        """

        if(self.properties_path == None):
            return False

        config = open(self.properties_path, 'r')

        disabled = False
        for line in config_file:
            if line == 'deployment.security.askgrantdialog.notinca':
                locked = True
        config.close()
        return locked

    def publisher_revocation_enabled(self):
        """Check SV-43604r1_rule: The dialog to enable users to 
        check publisher certificates for revocation must be enabled.

        Finding ID: V-32830     
        """

        if(self.properties_path == None):
            return False

        config = open(self.properties_path, 'r')

        disabled = False
        for line in config_file:
            if 'deployment.security.validation.crl=false' in line:
                locked = True
        config.close()
        return locked

    def publisher_revocation_locked(self):
        """Check SV-43617r1_rule: The option to enable users to check 
        publisher certificates for revocation must be locked.
        
        Finding ID: V-32831     
        """
        if(self.properties_path == None):
            return False

        config = open(self.properties_path, 'r')

        disabled = False
        for line in config_file:
            if 'deployment.security.validation.crl.locked' in line:
                locked = True
        config.close()
        return locked
        


    def certificate_validation_enabled(self):
        """Check SV-43649r1_rule: The option to enable online 
        certificate validation must be enabled.
        
        Finding ID: V-32832   
        """

        if(self.properties_path == None):
            return False

        config = open(self.properties_path, 'r')
        disabled = False
        for line in config_file:
            if 'deployment.security.validation.ocsp=false' in line:
                locked = True
        config.close()
        return locked
        

    def certificate_validation_locked(self):
        """Check SV-43619r1_rule: The option to enable online 
        certificate validation must be locked.

        Finding ID: V-32833      
        """
        if(self.properties_path == None):
            return False

        config = open(self.properties_path, 'r')
        locked = False
        for line in config_file:
            if line == 'deployment.security.validation.ocsp.locked':
                locked = True
        config.close()
        return locked

    def config_keys_set(self):
        """Check SV-43649r1_rule: The configuration file must contain
        proper keys and values to deploy settings correctly.
        
        Finding ID: V-32842    
        """
        if(self.properties_path == None):
            return False

        config = open(self.properties_path, 'r')
        properties_set = False
        deployment_set = False
        for line in config_file:
            if 'deployment.system.config=' in line: #This should end with properties filename
                properties_set = True
            if 'deployment.system.config.mandatory=false' in line:
                deployment_set = True
        config.close()
        return properties_set and deployment_set
        

if __name__ == "__main__":
    auditor = JREAuditor()
    auditor.audit_jre()
