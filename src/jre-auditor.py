

import os
from subprocess import call


DEPLOYMENT_FILENAME = "deployment.config"
PROPERTIES_FILENAME = "deployment.properties"
HOLDER_FILE = "hold.txt"
HOLDER_DIR = "./hold.txt"


class JREAuditor:

    def __init__(self):
        self.this = 3
        self.deployment_file = None
        self.properties_file = None
        self.deployment_path = None
        self.properties_path = None
        self.get_deployment_path()
        self.get_properties_path()

    def audit_jre(self):
        self.has_deployment_file()
        self.has_properties_file()

    def get_deployment_path(self):
        holder = open(HOLDER_FILE, 'w')
        call(["find", "/usr", "-name", DEPLOYMENT_FILENAME], stdout=holder)
        holder.close()
        holder = open(HOLDER_FILE, 'r')


        if(os.path.getsize(HOLDER_DIR) == 0):
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
        holder = open(HOLDER_FILE, 'w')
        call(["find", "/usr", "-name", PROPERTIES_FILENAME], stdout=holder)
        holder.close()
        holder = open(HOLDER_FILE, 'r')

        if(os.path.getsize(HOLDER_DIR) == 0):
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



    def permission_dialog_locked(self):
        """Check SV-43601r1_rule: The dialog to enable users to grant 
        permissions to execute signed content from an un-trusted 
        authority must be disabled.

        Finding ID: V-32829
        """
        config = open(self.properties_path, 'r')

        locked = False
        for line in config_file:
            if line == 'deployment.security.askgrantdialog.notinca':
                locked = True
        return locked



    def permission_dialog_disabeld(self):
        """Check SV-43596r1_rule: The dialog to enable users to grant 
        permissions to execute signed content from an un-trusted 
        authority must be disabled.

        Finding ID: V-32828     
        """
        config = open(self.properties_path, 'r')

        locked = False
        for line in config_file:
            if line == 'deployment.security.askgrantdialog.notinca=false':
                locked = True
        return locked

    


if __name__ == "__main__":
    auditor = JREAuditor()
    auditor.audit_jre()
