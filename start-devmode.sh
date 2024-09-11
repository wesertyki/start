#!/bin/sh

 mount -o bind /media/cryptofs/root/etc /etc
 telnetd -l /bin/sh
 
  # FIXME: disable this to turn off script echo
 set -x
 
 # FIXME: disable this to stop script from bailing on error
 # set -e
 
 # TODO: Check upstart daemon/process tracking (do we need to change /etc/init/devmode.conf? start sshd as daemon?)
  
 # set devmode ssh port here
 SSH_PORT="9922"

 
 # set arch:
 ARCH="armv71"
 grep -qs "qemux86" /etc/hostname && ARCH="i686"
 
 # set directories
 OPT_DEVMODE="/opt/devmode"
 OPT_SSH="/opt/openssh"
 DEVELOPER_HOME="/media/developer"
 DEVMODE_SERVICE_DIR="/media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service"
 CRYPTO_SSH="$DEVMODE_SERVICE_DIR/binaries-${ARCH}/opt/openssh"
 CRYPTO_OPT="$DEVMODE_SERVICE_DIR/binaries-${ARCH}/opt"

  
 if [ -s ${DEVMODE_SERVICE_DIR}/jail_app.conf ] ; then
 mv ${DEVMODE_SERVICE_DIR}/jail_app.conf ${DEVELOPER_HOME}
 mv ${DEVMODE_SERVICE_DIR}/jail_app.conf.sig ${DEVELOPER_HOME}
 fi
 
 if [ -r ${DEVMODE_SERVICE_DIR}/sessionToken ] ; then
 mv -f ${DEVMODE_SERVICE_DIR}/sessionToken /var/luna/preferences/devmode_enabled
 fi
 
 
 # Make sure the ssh binaries are executable (in service directory)
 if [ ! -x "${CRYPTO_SSH}/sbin/sshd" ] ; then
 chmod ugo+x ${CRYPTO_SSH}/sbin/sshd ${CRYPTO_SSH}/bin/ssh* ${CRYPTO_SSH}/bin/scp* || true
 chmod ugo+x ${CRYPTO_SSH}/bin/sftp ${CRYPTO_SSH}/lib/openssh/* || true
 chmod ugo+x ${CRYPTO_OPT}/devmode/usr/bin/* || true
 fi
 
 # TODO: (later) Look for "re-init" flag to re-generate ssh key if requested by app (via devkey service)
 # com.palm.service.devmode could have "resetKey" method to erase /var/lib/devmode/ssh/webos_rsa
 # Kind of dangerous though, since new key will need to be fetched on the desktop (after reboot)...
 # We could just require a hard-reset of the TV which should blow away /var/lib/devmode/ssh/...
 
 # Initialize the developer (client) SSH key pair, if it doesn't already exist
 if [ ! -e /var/lib/devmode/ssh/webos_rsa ] ; then
 mkdir -p /var/lib/devmode/ssh
 chmod 0700 /var/lib/devmode/ssh
 # get FIRST six (UPPER-CASE, hex) characters of 40-char nduid from nyx-cmd
 # NOTE: This MUST match passphrase as displayed in devmode app (main.js)!
# PASSPHRASE="`/usr/bin/nyx-cmd DeviceInfo query nduid | head -c 6 | tr 'a-z' 'A-Z'`"
  # PASSPHRASE="`/usr/bin/nyx-cmd DeviceInfo query nduid | tail -n1 | head -c 6 | tr 'a-z' 'A-Z'`"
 PASSPHRASE="`tail /var/lib/secretagent/nduid -c 40 | head -c 6 | tr 'a-z' 'A-Z'`"
 ${CRYPTO_SSH}/bin/ssh-keygen -t rsa -C "developer@device" -N "${PASSPHRASE}" -f /var/lib/devmode/ssh/webos_rsa
 # copy ssh key to /var/luna/preferences so the devmode service's KeyServer can read it and serve to ares-webos-cli tools
 cp -f /var/lib/devmode/ssh/webos_rsa /var/luna/preferences/webos_rsa
 chmod 0644 /var/luna/preferences/webos_rsa
 # if we generated a new ssh key, make sure we re-create the authorized_keys file
 rm -f ${DEVELOPER_HOME}/.ssh/authorized_keys
 fi
 
 # Make sure the /media/developer (and log) directories exists (as sam.conf erases it when devmode is off):
 mkdir -p ${DEVELOPER_HOME}/log
 chmod 777 ${DEVELOPER_HOME} ${DEVELOPER_HOME}/log
 
 # Install the SSH key into the authorized_keys file (if it doesn't already exist)
 if [ ! -e ${DEVELOPER_HOME}/.ssh/authorized_keys ] ; then
 mkdir -p ${DEVELOPER_HOME}/.ssh
 cp -f /var/lib/devmode/ssh/webos_rsa.pub ${DEVELOPER_HOME}/.ssh/authorized_keys || true
 # NOTE: authorized_keys MUST be world-readable else sshd can't read it inside the devmode jail
 # To keep sshd from complaining about that, we launch sshd with -o "StrictModes no" (below).
 chmod 755 ${DEVELOPER_HOME}/.ssh
 chmod 644 ${DEVELOPER_HOME}/.ssh/authorized_keys
 chown -R developer:developer ${DEVELOPER_HOME}/.ssh
 fi
 
 # FIXME: Can we move this to /var/run/devmode/sshd ?
 # Create PrivSep dir
 mkdir -p /var/run/sshd
 chmod 0755 /var/run/sshd
 
 # Create directory for host keys (rather than /opt/openssh/etc/ssh/)
 HOST_KEY_DIR="/var/lib/devmode/sshd"
 if [ ! -d "${HOST_KEY_DIR}" ] ; then
 mkdir -p ${HOST_KEY_DIR}
 chmod 0700 ${HOST_KEY_DIR}
 fi
 
 # Create initial keys if necessary
 if [ ! -f ${HOST_KEY_DIR}/ssh_host_rsa_key ]; then
 echo "  generating ssh RSA key..."
 ${CRYPTO_SSH}/bin/ssh-keygen -q -f ${HOST_KEY_DIR}/ssh_host_rsa_key -N '' -t rsa
 fi
 if [ ! -f ${HOST_KEY_DIR}/ssh_host_ecdsa_key ]; then
 echo "  generating ssh ECDSA key..."
 ${CRYPTO_SSH}/bin/ssh-keygen -q -f ${HOST_KEY_DIR}/ssh_host_ecdsa_key -N '' -t ecdsa
 fi
 if [ ! -f ${HOST_KEY_DIR}/ssh_host_dsa_key ]; then
 echo "  generating ssh DSA key..."
 ${CRYPTO_SSH}/bin/ssh-keygen -q -f ${HOST_KEY_DIR}/ssh_host_dsa_key -N '' -t dsa
 fi
 
 # Check config
 # NOTE: This should only be enabled for testing
 #${CRYPTO_SSH}/sbin/sshd -f ${CRYPTO_SSH}/etc/ssh/sshd_config -h ${HOST_KEY_DIR}/ssh_host_rsa_key -t
 
 # Set jailer command
 DEVMODE_JAIL="/usr/bin/jailer -t native_devmode -i com.palm.devmode.openssh -p ${DEVELOPER_HOME}/ -s /bin/sh"
 #DEVMODE_JAIL="echo"
 
 # Add for debugging, but this will cause sshd to exit after the first ssh login:
 # -ddd -e \
 
 # Make environment file for openssh
 DEVMODE_JAIL_CONF="/etc/jail_native_devmode.conf"
 DEVMODE_OPENSSH_ENV="${DEVELOPER_HOME}/.ssh/environment"
 if [ -f ${DEVMODE_JAIL_CONF} ]; then
 echo " generating environment file from jail_native_devmode.conf..."
 find ${DEVMODE_JAIL_CONF} | xargs awk '/setenv/{printf "%s=%s\n", $2,$3}' > ${DEVMODE_OPENSSH_ENV}
 ${DEVMODE_JAIL} /usr/bin/env >> ${DEVMODE_OPENSSH_ENV}
 fi
 # Set path for devmode
 if [ -f ${DEVMODE_OPENSSH_ENV} ]; then
 echo "PATH=${PATH}:${OPT_DEVMODE}/usr/bin" >> ${DEVMODE_OPENSSH_ENV}
 fi
 
 sleep 5;
 for interface in $(ls /sys/class/net/ | grep -v -e lo -e sit);
 do
 if [ -r /sys/class/net/$interface/carrier ] ; then
if [[ $(cat /sys/class/net/$interface/carrier) == 1 ]]; then OnLine=1; fi
fi
done
#if [ $OnLine ]; then
#sessionToken=$(cat /var/luna/preferences/devmode_enabled);
#checkSession=$(curl --max-time 3 -s https://developer.lge.com/secure/CheckDevModeSession.dev?sessionToken=$sessionToken);

#if [ "$checkSession" != "" ] ; then
#result=$(node -pe 'JSON.parse(process.argv[1]).result' "$checkSession");
#if [ "$result" == "success" ] ; then
rm -rf /var/luna/preferences/dc*;
## create devSessionTime file to remain session time in devmode app
#remainTime=$(node -pe 'JSON.parse(process.argv[1]).errorMsg' "$checkSession");
#resultValidTimeCheck=$(echo "${remainTime}" | egrep "^([0-9]{1,4}(:[0-5][0-9]){2})$");
#if [ "$resultValidTimeCheck" != "" ] ; then
 echo '90000:00:00' > ${DEVMODE_SERVICE_DIR}/devSessionTime;
 chgrp 5000 ${DEVMODE_SERVICE_DIR}/devSessionTime;
 chmod 664 ${DEVMODE_SERVICE_DIR}/devSessionTime;
#fi
#elif [ "$result" == "fail" ] ; then
#rm -rf /var/luna/preferences/devmode_enabled;
#rm -rf /var/luna/preferences/dc*;
#if [ -e ${DEVMODE_SERVICE_DIR}/devSessionTime ] ; then
#rm ${DEVMODE_SERVICE_DIR}/devSessionTime;
#fi
#fi
#fi
#fi

# Cache clear function added (except Local storage)
if [ -e ${DEVMODE_SERVICE_DIR}/devCacheClear ] ; then
rm -rf `ls | find /var/lib/webappmanager*/* -name "Local Storage" -o -name "localstorage" -prune -o -print`;
rm ${DEVMODE_SERVICE_DIR}/devCacheClear;
fi

# Launch sshd
${DEVMODE_JAIL} ${OPT_SSH}/sbin/sshd \
  -o StrictModes=no \
 -f ${OPT_SSH}/etc/ssh/sshd_config \
-h ${HOST_KEY_DIR}/ssh_host_rsa_key \
  -o PasswordAuthentication=no -o PermitRootLogin=no -o PermitUserEnvironment=yes \
 -D -p ${SSH_PORT}
