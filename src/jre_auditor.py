
import sys
import os
from subprocess import call
from jre_logger import JRELogger

DEPLOYMENT_FILENAME = "deployment.config"
PROPERTIES_FILENAME = "deployment.properties"
JRE_HOLDER_FILE = "jre_hold.txt"
JRE_HOLDER_DIR = "./jre_hold.txt"


class JREAuditor:
    """ Finds the configuration files for the java runtime environment 
    and checks to see if they are configured to be compliant with the
    JRE STIG put out by the DIA.

    Only supports configuartion of JRE 7 STIG on a nix system. Does not check if
    latest version.
    """
    def __init__(self):
        self.deployment_file = None
        self.properties_file = None
        self.deployment_path = None
        self.properties_path = None
        self.os = sys.platform
        self.get_deployment_path()
        self.get_properties_path()
        

    def audit(self):
        """
        Run checks of the JRE for compliance and report all misconfiguartions using
        the JRELogger.
        """
        logger = JRELogger()

        success = self.has_deployment_file()
        logger.has_deployment_file_errmsg(success)
        success = self.has_properties_file()
        logger.has_properties_file_errmsg(success)
        success = self.permission_dialog_disabled()
        success = self.permission_dialog_locked()
        logger.permission_dialog_locked_errmsg(success)
        success = self.publisher_revocation_enabled()
        logger.publisher_revocation_enabled_errmsg(success)
        success = self.publisher_revocation_locked()
        logger.publisher_revocation_locked_errmsg(success)
        success = self.certificate_validation_enabled()
        logger.certificate_validation_enabled_errmsg(success)
        success = self.certificate_validation_locked()
        logger.certificate_validation_locked_errmsg(success)
        success = self.config_keys_set()
        logger.config_keys_set_errmsg(success)
        success = self.check_jre_version()
        logger.check_jre_version_errmsg(success)
        success = self.check_no_outdated()
        logger.check_no_outdated_errmsg(success)
        
        self.clean()
        del logger
    

    def __del__(self):
        self.clean()

    def clean(self):
        call(["rm", JRE_HOLDER_FILE])
        if self.deployment_file != None:
            self.deployment_file.close()
        if self.properties_file != None: 
            self.properties_file.close()     

    def get_deployment_path(self):
        """ Searches the system for config file with the default deployment 
        filename.
        """
        if("linux" in self.os):
            holder = open(JRE_HOLDER_FILE, 'w')
            call(["find", "/usr", "-name", DEPLOYMENT_FILENAME], stdout=holder)
            holder.close()
            holder = open(JRE_HOLDER_FILE, 'r')
        else:
            print("Windows system1")

        if(os.path.getsize(JRE_HOLDER_DIR) == 0):
            self.deployment_path = None
            return 0

        for file in holder:
            if(line != ''):
                self.deployment_path = line
                holder.close()
                return 1
            else:
                self.deployment_path = None
                holder.close()
                return 0

    def get_properties_path(self):
        """ Searches the system for the JRE properties file.
        """
        if("linux" in self.os):
            holder = open(JRE_HOLDER_FILE, 'w')
            call(["find", "/usr", "-name", PROPERTIES_FILENAME], stdout=holder)
            holder.close()
        else:
            print("Windows system2")

        if(os.path.getsize(JRE_HOLDER_DIR) == 0):
            self.deployment_path = None
            return 0
        
        holder = open(JRE_HOLDER_FILE, 'r')
        for file in holder:
            if(line != ''):
                self.deployment_path = line
                holder.close()
                return 1
            else:
                self.deployment_path = None
                holder.close()
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
        """Check SV-43618r1_rule: The option to enable online 
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

    def check_jre_version(self):
        """Check SV-51133r1_rule: The version of the JRE running on 
        the system must be the most current available.

        Finding ID: V-61037
        
        Currently don't have a way to reliable check!!!!!!
        """ 
        holder = open(JRE_HOLDER_FILE, 'w')
        call(["java", "-version"], stdout=holder)
        holder.close()

    def check_no_outdated(self):
        """Check SV-75505r2_rule: Java Runtime Environment versions 
        that are no longer supported by the vendor for security 
        updates must not be installed on a system.
        
        Finding ID: V-61037   
        """       
        pass



if __name__ == "__main__":
    auditor = JREAuditor()
    auditor.audit_jre()
    del auditor
