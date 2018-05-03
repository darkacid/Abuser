# Abuser
A Zimbra Audit auth log parser script and AbuseIPDB checker. Parse auth logs, check IP in AbuseIPDB and send an email to admin.

Note:
    To autostart on Linux (systemd): Copy zimbraAuditParse.service to /lib/systemd/system/zimbraAuditParse.service, and change the directories in the .service file.