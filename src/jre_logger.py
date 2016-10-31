
# Put in holder errmsgs for now...
class JRELogger:
    def __init__(self, filename="JRELog.txt"):
        self.filename = filename
        self.log = open(filename, 'w')

    def has_deployment_file_errmsg(self, success):
        if not success:
           log.write("Check SV-43621r1_rule\n")
    def has_properties_file_errmsg(self, success):
         if not success:
            log.write("Check SV-43620r1_rule\n")

    def permission_dialog_disabled_errmsg(self, success):
        if not success:
             log.write("Check SV-43596r1_rule\n")

    def permission_dialog_locked_errnsg(self, success):
        if not success:
             log.write("Check V-32901_rule\n")

    def publisher_revocation_enabled_errmsg(self, success):
        if not success:
            log.write("Check V-32901_rule\n")

    def publisher_revocation_locked_errmsg(self, success):
        if not success:
            log.write("Check V-32901_rule\n")

    def certificate_validation_enabled_errmsg(self, success):
        if not success:
            log.write("Check V-32901_rule\n")

    def certificate_validation_locked_errmsg(self, success):
        if not success:
            log.write("Check V-32901_rule\n")

    def config_keys_set_errmsg(self, success):
        if not success:
            log.write("Check SV-43621r1_rule\n")
        
    def __del__(self):
        self.log.close()
