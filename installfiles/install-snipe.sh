#! /bin/bash

#############################################################################
#                                                                           #
# Author:       Martin Boller                                               #
#                                                                           #
# Email:        martin@bollers.dk                                           #
# Last Update:  2022-01-11                                                  #
# Version:      1.10                                                        #
#                                                                           #
# Changes:      Initial Version (1.00)                                      #
#               https in .env file or logo / pictures doesn't show (1.10)   #
#                                                                           #
# Info:         Installing Snipe-IT on Debian 11                            #
#               Most of the work done by the install                        #
#                  Script created by Mike Tucker                            #
#                   mtucker6784@gmail.com                                   #
#                                                                           #
# Instruction:  Run this script as root on a fully updated                  #
#               Debian 10 (Buster) or Debian 11 (Bullseye)                  #
#                                                                           #
#############################################################################


install_prerequisites() {
    /usr/bin/logger 'install_prerequisites' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - install_prerequisites"
    echo -e "\e[1;36m ... installing Prerequisite packages\e[0m";
    tzone=$(cat /etc/timezone)
    export DEBIAN_FRONTEND=noninteractive;
    # Install prerequisites
    #echo -e "\e[1;36m ... adding PHP repository.\e[0m"
    apt-get -qq -y install apt-transport-https lsb-release ca-certificates > /dev/null 2>&1
    wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg > /dev/null 2>&1
    echo "deb https://packages.sury.org/php/ $codename main" > /etc/apt/sources.list.d/php.list
    echo -e "\e[1;36m ... updating all packages\e[0m";
    apt-get -qq update > /dev/null 2>&1;
    # Install some basic tools on a Debian net install
    /usr/bin/logger '..Install some basic tools on a Debian net install' -t 'snipeit-2022-01-10';
    echo -e "\e[1;36m ... installing packages missing from Debian net-install\e[0m";
    apt-get -qq -y install --fix-policy > /dev/null 2>&1;
    apt-get -qq -y install adduser wget whois unzip curl gnupg2 software-properties-common dnsutils python3 python3-pip > /dev/null 2>&1;

    echo -e "\e[1;36m ... installing MariaDB, Apache Web Server, and other required packages\e[0m" 
    apt-get -qq -y install mariadb-server mariadb-client apache2 apache2-utils curl git unzip > /dev/null 2>&1
    echo -e "\e[1;36m ... installing PHP packages needed\e[0m" 
    apt-get -qq -y install libapache2-mod-php7.4 php7.4 php7.4-mcrypt php7.4-curl php7.4-mysql php7.4-gd php7.4-ldap php7.4-zip php7.4-mbstring php7.4-xml php7.4-bcmath > /dev/null 2>&1
    # composer check-platform-reqs throws an error with php 8.x as it is currently only checking for 6.x or 7.x
    # Thus reverted back to installing 7.4 (see above)
    #apt-get -qq -y install libapache2-mod-php php php-mcrypt php-curl php-mysql php-gd php-ldap php-zip php-mbstring php-xml php-bcmath > /dev/null 2>&1
    # Some additional libraries for php-gd
    apt-get -qq -y install libpng-dev libjpeg-dev libwebp-dev libgd2-xpm-dev* > /dev/null 2>&1
    # Set locale
    # Install other preferences and clean up APT
    echo -e "\e[1;36m ... installing some preferences on Debian and cleaning up apt\e[0m";
    /usr/bin/logger '....installing some preferences on Debian and cleaning up apt' -t 'snipeit-2022-01-10';
    apt-get -qq -y install bash-completion > /dev/null 2>&1;
    # Install SUDO
    apt-get -qq -y install sudo > /dev/null 2>&1;
    # A little apt 
    apt-get -qq -y install --fix-missing > /dev/null 2>&1;
    apt-get -qq update > /dev/null 2>&1;
    apt-get -qq -y full-upgrade > /dev/null 2>&1;
    apt-get -qq -y autoremove --purge > /dev/null 2>&1;
    apt-get -qq -y autoclean > /dev/null 2>&1;
    apt-get -qq -y clean > /dev/null 2>&1;
    # Python pip packages
    echo -e "\e[1;36m ... installing python3-pip\e[0m";
    apt-get -qq -y python3-pip > /dev/null 2>&1;
    python3 -m pip install --upgrade pip > /dev/null 2>&1;
    echo -e "\e[1;32m - install_prerequisites finished"
    /usr/bin/logger 'install_prerequisites finished' -t 'snipeit-2022-01-10';
}

generate_certificates() {
    /usr/bin/logger 'generate_certificates()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - generate_certificates"
    mkdir -p $APACHE_CERTS_DIR > /dev/null 2>&1;
    echo -e "\e[1;36m ... generating openssl.cnf file\e[0m";
    cat << __EOF__ > ./openssl.cnf
## Request for $fqdn
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
encrypt_key = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
countryName         = $ISOCOUNTRY
stateOrProvinceName = $PROVINCE
localityName        = $LOCALITY
organizationName    = $ORGNAME
CN = $fqdn

[ req_ext ]
subjectAltName = $ALTNAMES
__EOF__
    sync;
    # generate Certificate Signing Request to send to corp PKI
    echo -e "\e[1;36m ... generating csr and private key\e[0m";
    openssl req -new -config openssl.cnf -keyout $APACHE_CERTS_DIR/$fqdn.key -out $APACHE_CERTS_DIR/$fqdn.csr > /dev/null 2>&1
    # generate self-signed certificate (remove when CSR can be sent to Corp PKI)
    echo -e "\e[1;36m ... generating self signed certificate\e[0m";
    openssl x509 -in $APACHE_CERTS_DIR/$fqdn.csr -out $APACHE_CERTS_DIR/$fqdn.crt -req -signkey $APACHE_CERTS_DIR/$fqdn.key -days 365 > /dev/null 2>&1
    chmod 600 $APACHE_CERTS_DIR/$fqdn.key > /dev/null 2>&1
    echo -e "\e[1;32m - generate_certificates finished"
    /usr/bin/logger 'generate_certificates() finished' -t 'snipeit-2022-01-10';
}

letsencrypt_certificates() {
    /usr/bin/logger 'letsencrypt_certificates()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - letsencrypt_certificates()"

     echo -e "\e[1;36m ... installing certbot\e[0m";
    apt-get -y -qq install certbot python3-certbot-apache > /dev/null 2>&1
    sync;

    # Start certbot'ing
    echo -e "\e[1;36m ... running certbot\e[0m";
    certbot run -n --agree-tos --apache -m $mailaddress --domains $fqdn

    echo -e "\e[1;36m ... creating cron job for automatic renewal of certificates\e[0m";
        cat << __EOF__ > /etc/cron.weekly/certbot
#!/bin/sh
/usr/bin/certbot renew
__EOF__
    chmod 755 /etc/cron.weekly/certbot > /dev/null 2>&1
    echo -e "\e[1;32m - letsencrypt_certificates() finished"
    /usr/bin/logger 'letsencrypt_certificates() finished' -t 'snipeit-2022-01-10';
}

prepare_nix() {
    /usr/bin/logger 'prepare_nix()' -t 'gse-21.4';
    echo -e "\e[1;32m - prepare_nix"

    echo -e "\e[1;36m ... creating some permanent variables for Snipe-IT\e[0m";    
     # Update Snipe-IT environment variables
    cat << __EOF__ > /etc/profile.d/snipeitvars.sh
export APP_USER="snipeitapp"
export APP_NAME="snipeit"
export APP_PATH="/var/www/html/$APP_NAME"
export APP_CONFIG_PATH="$APP_PATH/.env"
__EOF__
    chmod 744 /etc/profile.d/snipeitvars.sh

    echo -e "\e[1;36m ... generating motd file\e[0m";    
    # Configure MOTD
    BUILDDATE=$(date +%Y-%m-%d)
    cat << __EOF__ >> /etc/motd
           
*****************************************************        
*      _____       _                  __________    *
*     / ___/____  (_)___  ___        /  _/_  __/    *
*     \__ \/ __ \/ / __ \/ _ \______ / /  / /       *
*    ___/ / / / / / /_/ /  __/_____// /  / /        *
*   /____/_/ /_/_/ .___/\___/     /___/ /_/         *
*               /_/                                 *
*                                                   *
********************||*******************************
             (\__/) ||
             (•ㅅ•) ||
            /  　  づ
         Automated install v  1.10
                2022-01-10

__EOF__
    echo -e "\e[1;36m ... configuring motd display\e[0m";
    # do not show motd twice
    sed -ie 's/session    optional     pam_motd.so  motd=\/etc\/motd/#session    optional     pam_motd.so  motd=\/etc\/motd/' /etc/pam.d/sshd > /dev/null 2>&1
    sync;
    echo -e "\e[1;32m - prepare_nix() finished"
    /usr/bin/logger 'prepare_nix() finished' -t 'snipeit-2022-01-10';
}

configure_apache() {
    /usr/bin/logger 'configure_apache()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - configure_apache()"
    # Change ROOTCA to point to correct cert when/if not using self signed cert.
    export ROOTCA=$fqdn
    # Enable Apache modules required
    echo -e "\e[1;36m ... adding additional apache modules\e[0m";
    a2enmod rewrite ssl headers > /dev/null 2>&1;
    echo -e "\e[1;36m ... enabling $APP_NAME site\e[0m";
    # TLS
    echo -e "\e[1;36m ... generating site configuration file with TLS support\e[0m";

    # Disabling TLSv1.2 breaks some reverse proxies, such as the popular NGINX Reverse Proxy.  Ask the user if they wish to disable TLSv1.2, and modify the Apache configuation we're setting appropriately.
    # I know there are better ways to do this but I've been troubleshooting this issue for a while and I just want it to work now.
    tls1dot2=default
    until [[ $tls1dot2 == "yes" ]] || [[ $tls1dot2 == "no" ]]; do
    echo -e "\e[1;32m"
    echo -n "  Q. Do you want to disable TLSv1.2? It is more secure, but may interfere with reverse proxies.  If you are using a reverse proxy, you may want to select no; otherwise, select yes. (y/n) "
    read -r tls1dot2

    case $tls1dot2 in
    [yY] | [yY][Ee][Ss] )
        cat << __EOF__ > $APACHE_DIR/sites-available/snipeit.conf;
    <VirtualHost *:80>
        ServerName $fqdn
        RewriteEngine On
        RewriteCond %{REQUEST_URI} !^/\.well\-known/acme\-challenge/
        RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]
    </VirtualHost>

    <VirtualHost *:443>
        <Directory $APP_PATH/public>
            Allow From All
            AllowOverride All
            Options -Indexes
        </Directory>

        ServerName $fqdn
        DocumentRoot $APP_PATH/public
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
    
        SSLCertificateFile "$APACHE_CERTS_DIR/$fqdn.crt"
        SSLCertificateKeyFile "$APACHE_CERTS_DIR/$fqdn.key"
        SSLCertificateChainFile "$APACHE_CERTS_DIR/$ROOTCA.crt"

        # enable HTTP/2, if available
        Protocols h2 http/1.1

        # HTTP Strict Transport Security (mod_headers is required)
        Header always set Strict-Transport-Security "max-age=63072000"
    </VirtualHost>

    # modern configuration
    SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2
    SSLHonorCipherOrder     off
    SSLSessionTickets       off
    # Cert Stapling
    SSLUseStapling On
    SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
__EOF__
        tls1dot2="yes"
        ;;
    [nN] | [n|N][O|o] )
        cat << __EOF__ > $APACHE_DIR/sites-available/snipeit.conf;
    <VirtualHost *:80>
        ServerName $fqdn
        RewriteEngine On
        RewriteCond %{REQUEST_URI} !^/\.well\-known/acme\-challenge/
        RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]
    </VirtualHost>

    <VirtualHost *:443>
        <Directory $APP_PATH/public>
            Allow From All
            AllowOverride All
            Options -Indexes
        </Directory>

        ServerName $fqdn
        DocumentRoot $APP_PATH/public
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
    
        SSLCertificateFile "$APACHE_CERTS_DIR/$fqdn.crt"
        SSLCertificateKeyFile "$APACHE_CERTS_DIR/$fqdn.key"
        SSLCertificateChainFile "$APACHE_CERTS_DIR/$ROOTCA.crt"

        # enable HTTP/2, if available
        Protocols h2 http/1.1

        # HTTP Strict Transport Security (mod_headers is required)
        Header always set Strict-Transport-Security "max-age=63072000"
    </VirtualHost>

    # modern configuration
    SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder     off
    SSLSessionTickets       off
    # Cert Stapling
    SSLUseStapling On
    SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
__EOF__
        tls1dot2="no"
        ;;
    *)  echo -e "\e[1;31m - Invalid answer. Please type y or n\e[0m"
        ;;
    esac
    done

    echo -e "\e[1;36m ... turning of some apache specific header information\e[0m";
    # Turn off detail Header information
    cat << __EOF__ >> $APACHE_DIR/apache2.conf;
ServerTokens Prod
ServerSignature Off
FileETag None
__EOF__
    sync;
        echo -e "\e[1;36m ... setting $APP_NAME permissions\e[0m";
    for chmod_dir in "$APP_PATH/storage" "$APP_PATH/public/uploads"; do
        chmod -R 775 "$chmod_dir" > /dev/null 2>&1
    done
    chown -R $APP_USER:$apache_group $APP_PATH/
    echo -e "\e[1;36m ... restarting apache with new configuration\e[0m";
    a2ensite $APP_NAME.conf > /dev/null 2>&1
    systemctl restart apache2.service > /dev/null 2>&1;
    echo -e "\e[1;32m - configure_apache() finished"
    /usr/bin/logger 'configure_apache() finished' -t 'snipeit-2022-01-10';
}

configure_iptables() {
    /usr/bin/logger 'configure_iptables() started' -t 'bSIEM Step2';
    echo -e "\e[32m - configure_iptables()\e[0m";
    echo -e "\e[36m ... creating iptables rules file for IPv4\e[0m";
    cat << __EOF__  >> /etc/network/iptables.rules
##
## Ruleset for snipeit Server
##
## IPTABLES Ruleset Author: Martin Boller 2021-11-11 v1

*filter
## Dropping anything not explicitly allowed
##
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOG_DROPS - [0:0]

## DROP IP fragments
-A INPUT -f -j LOG_DROPS
-A INPUT -m ttl --ttl-lt 4 -j LOG_DROPS

## DROP bad TCP/UDP combinations
-A INPUT -p tcp --dport 0 -j LOG_DROPS
-A INPUT -p udp --dport 0 -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROPS

## Allow everything on loopback
-A INPUT -i lo -j ACCEPT

## SSH, DNS, WHOIS, DHCP ICMP - Add anything else here needed for ntp, monitoring, dhcp, icmp, updates, and ssh
##
## SSH
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
## HTTP(S)
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
## NTP
-A INPUT -p udp -m udp --dport 123 -j ACCEPT
## ICMP
-A INPUT -p icmp -j ACCEPT
## Already established sessions
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

## Logging
-A INPUT -j LOG_DROPS
## get rid of broadcast noise
-A LOG_DROPS -d 255.255.255.255 -j DROP
# Drop Broadcast to internal networks
-A LOG_DROPS -m pkttype --pkt-type broadcast -d 192.168.0.0/16 -j DROP
-A LOG_DROPS -p ip -m limit --limit 60/sec -j --log-prefix "iptables:" --log-level 7
-A LOG_DROPS -j DROP

## Commit everything
COMMIT
__EOF__

    echo -e "\e[36m ... creating iptables rules file for IPv6\e[0m";
# ipv6 rules
    cat << __EOF__  >> /etc/network/ip6tables.rules
##
## Ruleset for spiderfoot Server
##
## IP6TABLES Ruleset Author: Martin Boller 2021-11-11 v1

*filter
## Dropping anything not explicitly allowed
##
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOG_DROPS - [0:0]

## DROP bad TCP/UDP combinations
-A INPUT -p tcp --dport 0 -j LOG_DROPS
-A INPUT -p udp --dport 0 -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROPS

## Allow everything on loopback
-A INPUT -i lo -j ACCEPT

## Allow access to port 5001
-A OUTPUT -p tcp -m tcp --dport 5001 -j ACCEPT
## SSH, DNS, WHOIS, DHCP ICMP - Add anything else here needed for ntp, monitoring, dhcp, icmp, updates, and ssh
## SSH
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
## HTTP(S)
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
## NTP
-A INPUT -p udp -m udp --dport 123 -j ACCEPT
## ICMP
-A INPUT -p icmp -j ACCEPT
## Already established sessions
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

## Logging
-A INPUT -j LOG_DROPS
-A LOG_DROPS -p ip -m limit --limit 60/sec -j --log-prefix "iptables:" --log-level 7
-A LOG_DROPS -j DROP

## Commit everything
COMMIT
__EOF__

    # Configure separate file for iptables logging
    echo -e "\e[36m ... configuring separate file for iptables\e[0m";
    cat << __EOF__  >> /etc/rsyslog.d/30-iptables-syslog.conf
:msg,contains,"iptables:" /var/log/iptables.log
& stop
__EOF__
    sync;
    systemctl restart rsyslog.service> /dev/null 2>&1;

    # Configure daily logrotation (forward this to mgmt)
    echo -e "\e[36m ... configuring daily logrotation for iptables log\e[0m";
    cat << __EOF__  >> /etc/logrotate.d/iptables
/var/log/iptables.{
  rotate 5
  daily
  compress
  create 640 root root
  notifempty
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
__EOF__

# Apply iptables at boot
    echo -e "\e[36m ... creating if-up script to apply iptables rules at every startup\e[0m";
    echo -e "\e[36m-Script applying iptables rules\e[0m";
    cat << __EOF__  >> /etc/network/if-up.d/firewallrules
#! /bin/bash
iptables-restore < /etc/network/iptables.rules
ip6tables-restore < /etc/network/ip6tables.rules
exit 0
__EOF__
    sync;
    ## make the script executable
    chmod +x /etc/network/if-up.d/firewallrules > /dev/null 2>&1;
    # Apply firewall rules for the first time
    #/etc/network/if-up.d/firewallrules;
    /usr/bin/logger 'configure_iptables() done' -t 'Firewall setup';
}

show_databases() {
    /usr/bin/logger 'show_databases()' -t 'snipeit-2022-01-10';
    echo -e ""
    echo -e "\e[1;32m------------------------------\e[0m"
    echo -e ""
    echo -e "\e[1;32mShowing databases....."
    mysql -e "show databases;"
    echo -e "\e[1;32m------------------------------\e[0m"
    /usr/bin/logger 'show_databases() finished' -t 'snipeit-2022-01-10';
}

check_services() {
    /usr/bin/logger 'check_services' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - check_services()"
    # Check status of critical services
    # Apache and MariaDB after restarting them
    echo -e "\e[1;36m ... restarting MariaDB\e[0m";
    systemctl restart mariadb.service  > /dev/null 2>&1
    echo -e "\e[1;36m ... restarting Apache Web Server\e[0m";
    #systemctl reload apache2.service  > /dev/null 2>&1
    systemctl restart apache2.service  > /dev/null 2>&1
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    echo -e "\e[1;32m - Checking core daemons for Snipe-IT......\e[0m";
    if systemctl is-active --quiet apache2.service;
        then
            echo -e "\e[1;32m ... apache webserver started successfully";
            /usr/bin/logger 'apache webserver started successfully' -t 'snipeit-2022-01-10';
        else
            echo -e "\e[1;31m ... apache webserver FAILED!\e[0m";
            /usr/bin/logger 'apache webserver FAILED' -t 'snipeit-2022-01-10';
    fi
    # mariadb.service
    if systemctl is-active --quiet mariadb.service;
        then
            echo -e "\e[1;32m ... mariadb.service started successfully";
            /usr/bin/logger 'mariadb.service started successfully' -t 'snipeit-2022-01-10';
        else
            echo -e "\e[1;31m ... mariadb.service FAILED!\e[0m";
            /usr/bin/logger "mariadb.service FAILED!" -t 'snipeit-2022-01-10';
    fi
    echo -e "\e[1;32m - check_services() finished"
    /usr/bin/logger 'check_services finished' -t 'snipeit-2022-01-10';
}

mariadb_secure_installation() {
    ## This function is based on the mysql-secure-installation script
    ## Provided with MariaDB
    /usr/bin/logger 'mariadb_secure_installation()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - mariadb_secure_installation()"
    echo -e "\e[1;36m ... securing MariaDB\e[0m"
    # Remove anonymous users
    echo -e "\e[1;36m ... removing anonymous users...\e[0m"
    /usr/bin/mysql -e "DELETE FROM mysql.global_priv WHERE User='';" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\e[1;32m ... Success: Anonymous users removed!\e[0m"
        /usr/bin/logger 'Success: Anonymous users removed' -t 'snipeit-2022-01-10';
    else
        echo -e "\e[1;31m ... Critical: Anonymous users could not be removed!\e[0m"
        /usr/bin/logger 'Critical: Anonymous users could not be removed' -t 'snipeit-2022-01-10';
    fi

    # Remove remote root 
    echo -e "\e[1;36m ... removing remote root...\e[0m"
    /usr/bin/mysql -e "DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\e[1;32m ... Success: Remote root successfully removed!\e[0m"
        /usr/bin/logger 'Success: Remote root removed' -t 'snipeit-2022-01-10';
    else
        echo -e "\e[1;31m ... Critical: Remote root could not be removed!\e[0m"
        /usr/bin/logger 'Critical: Remote root could not be removed' -t 'snipeit-2022-01-10';
    fi
    
    # Remove test database
    echo -e "\e[1;36m ... Dropping test database...\e[0m"
    /usr/bin/mysql -e "DROP DATABASE IF EXISTS test;" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\e[1;32m ... Success: Test database removed!\e[0m"
        /usr/bin/logger 'Success: Test database removed' -t 'snipeit-2022-01-10';
    else
        echo -e "\e[1;31m ... Warning: Test database could not be removed! Not critical...\e[0m"
        /usr/bin/logger 'Warning: Test database could not be removed' -t 'snipeit-2022-01-10';
    fi

    echo -e "\e[1;36m ... Removing privileges on test database...\e[0m"
    /usr/bin/mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\e[1;32m ... Success: privileges on test database removed!\e[0m"
        /usr/bin/logger 'Success: Privileges on test database removed' -t 'snipeit-2022-01-10';
    else
        echo -e "\e[1;33m ... Warning: privileges on test database not removed\e[0m"
        /usr/bin/logger 'Warning: Privileges on test database could not be removed' -t 'snipeit-2022-01-10';
    fi

    # Reload privilege tables
    echo -e "\e[1;36m ... reloading privilege tables...\e[0m"
    /usr/bin/mysql -e "FLUSH PRIVILEGES;" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\e[1;32m ... Success: privilege tables reloaded"
        return 0
    else
        echo -e "\e[1;33m ... Warning: privilege tables could not be reloaded"
        return 1
    fi
    /usr/bin/logger 'mariadb_secure_installation() finished' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - securing MariaDB finished\e[0m"
}

configure_mail_server() {
    /usr/bin/logger 'configure_mail_server()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - configure_mail_server()\e[0m"
    # Setting up mail server config

    ######################################################
    #       Originally from the Snipe-It Install         #
    #          Script created by Mike Tucker             #
    #            mtucker6784@gmail.com                   #
    ######################################################
    
    setupmail=default
    until [[ $setupmail == "yes" ]] || [[ $setupmail == "no" ]]; do
    echo -e "\e[1;32m"
    echo -n "  Q. Do you want to configure mail server settings? (y/n) "
    read -r setupmail

    case $setupmail in
    [yY] | [yY][Ee][Ss] )
        # Mail Server details
        # Server address or name
        echo -n " - Outgoing mailserver IP address or hostname (fqdn): "
        read -r mailhost
        sed -i "s|^\\(MAIL_HOST=\\).*|\\1$mailhost|" "$APP_PATH/.env"
        #port
        echo -n " - Server port number: "
        read -r mailport
        sed -i "s|^\\(MAIL_PORT=\\).*|\\1$mailport|" "$APP_PATH/.env"
        #username
        echo -n "  Username: "
        read -r mailusername
        sed -i "s|^\\(MAIL_USERNAME=\\).*|\\1$mailusername|" "$APP_PATH/.env"
        #password
        echo -n " - Password: "
        read -rs mailpassword
        sed -i "s|^\\(MAIL_PASSWORD=\\).*|\\1$mailpassword|" "$APP_PATH/.env"
        echo ""
        #encryption
        echo -n " - Encryption(null/TLS/SSL): "
        read -r mailencryption
        sed -i "s|^\\(MAIL_ENCRYPTION=\\).*|\\1$mailencryption|" "$APP_PATH/.env"

        # Account details
        #from address
        echo -n "  From address: "
        read -r mailfromaddr
        sed -i "s|^\\(MAIL_FROM_ADDR=\\).*|\\1$mailfromaddr|" "$APP_PATH/.env"
        #from name
        echo -n " - From name: "
        read -r mailfromname
        sed -i "s|^\\(MAIL_FROM_NAME=\\).*|\\1$mailfromname|" "$APP_PATH/.env"
        #reply to address
        echo -n " - Reply to address: "
        read -r mailreplytoaddr
        sed -i "s|^\\(MAIL_REPLYTO_ADDR=\\).*|\\1$mailreplytoaddr|" "$APP_PATH/.env"
        #reply to name
        echo -n " - Reply to name: "
        read -r mailreplytoname
        sed -i "s|^\\(MAIL_REPLYTO_NAME=\\).*|\\1$mailreplytoname|" "$APP_PATH/.env"
        echo -e "\e[0m"
        # Create file to indicate mail is configured
        touch $mailconfigFILE;
        setupmail="yes"
        ;;
    [nN] | [n|N][O|o] )
        setupmail="no"
        ;;
    *)  echo -e "\e[1;31m - Invalid answer. Please type y or n\e[0m"
        ;;
    esac
    done
    echo -e "\e[0m"
    /usr/bin/logger 'configure_mail_server() finished' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - configure_mail_server() finished\e[0m"
}

create_user () {
    echo -e "\e[1;32m - create_user()"
    echo -e "\e[1;36m ... creating Snipe-IT user $APP_USER.\e[0m"
    adduser --quiet --disabled-password --gecos 'Snipe-IT User' "$APP_USER" > /dev/null 2>&1
    echo -e "\e[1;36m ... adding Snipe-IT user to group $apache_group.\e[0m"
    usermod -a -G "$apache_group" "$APP_USER" > /dev/null 2>&1
    echo -e "\e[1;32m - create_user()"
}

install_composer () {
    
    ######################################################
    #       Originally from the Snipe-It Install         #
    #          Script created by Mike Tucker             #
    #            mtucker6784@gmail.com                   #
    ######################################################
    
    /usr/bin/logger 'install_composer()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - install_composer()"
    echo -e "\e[1;36m ... getting composer signature.\e[0m"
    # https://getcomposer.org/doc/faqs/how-to-install-composer-programmatically.md
    EXPECTED_SIGNATURE="$(wget -q -O - https://composer.github.io/installer.sig)" > /dev/null 2>&1
    sudo -i -u $APP_USER php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" > /dev/null 2>&1
    ACTUAL_SIGNATURE="$(sudo -i -u $APP_USER php -r "echo hash_file('SHA384', 'composer-setup.php');")" > /dev/null 2>&1

    if [ "$EXPECTED_SIGNATURE" != "$ACTUAL_SIGNATURE" ]
    then
        >&2 echo -e "\e[1;31m ... ERROR: Invalid composer installer signature\e[0m"
        sudo -i -u $APP_USER rm composer-setup.php > /dev/null 2>&1
        exit 1
    fi

    echo -e "\e[1;36m ... setting up composer as $APP_USER.\e[0m"
    sudo -i -u $APP_USER php composer-setup.php > /dev/null 2>&1
    sudo -i -u $APP_USER rm composer-setup.php > /dev/null 2>&1

    mv "$(eval echo ~$APP_USER)"/composer.phar /usr/local/bin/composer > /dev/null 2>&1
    echo -e "\e[1;32m - install_composer() finished"
    /usr/bin/logger 'install_composer() finished' -t 'snipeit-2022-01-10';
}

install_snipeit () {
    
    ######################################################
    #       Originally from the Snipe-It Install         #
    #          Script created by Mike Tucker             #
    #            mtucker6784@gmail.com                   #
    ######################################################
    
    /usr/bin/logger 'install_snipeit()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - install_snipeit()"
    echo -e "\e[1;36m ... create databases.\e[0m"
    mysql -u root --execute="CREATE DATABASE snipeit;GRANT ALL PRIVILEGES ON snipeit.* TO snipeit@localhost IDENTIFIED BY '$mysqluserpw';" > /dev/null 2>&1

    echo -e "\e[1;36m ... cloning Snipe-IT from github to $APP_PATH.\e[0m"
    git clone --quiet https://github.com/snipe/snipe-it $APP_PATH > /dev/null 2>&1

    echo -e "\e[1;36m ... configuring the $APP_NAME $APP_PATH/.env file.\e[0m"
    cp "$APP_PATH/.env.example" "$APP_PATH/.env" > /dev/null 2>&1

    #TODO escape SED delimiter in variables
    sed -i '1 i\#Created By Snipe-it Installer' "$APP_PATH/.env" > /dev/null 2>&1
    sed -i "s|^\\(APP_TIMEZONE=\\).*|\\1$tzone|" "$APP_PATH/.env" > /dev/null 2>&1
    sed -i "s|^\\(DB_HOST=\\).*|\\1localhost|" "$APP_PATH/.env" > /dev/null 2>&1
    sed -i "s|^\\(DB_DATABASE=\\).*|\\1snipeit|" "$APP_PATH/.env" > /dev/null 2>&1
    sed -i "s|^\\(DB_USERNAME=\\).*|\\1snipeit|" "$APP_PATH/.env" > /dev/null 2>&1
    sed -i "s|^\\(DB_PASSWORD=\\).*|\\1'$mysqluserpw'|" "$APP_PATH/.env" > /dev/null 2>&1
    sed -i "s|^\\(APP_URL=\\).*|\\1https://$fqdn|" "$APP_PATH/.env" > /dev/null 2>&1
    echo -e "\e[1;32m - install_snipeit() finished"
    /usr/bin/logger 'install_snipeit() finished' -t 'snipeit-2022-01-10';
}

set_hosts () {
    /usr/bin/logger 'set_hosts()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - set_hosts()"
    echo -e "\e[1;36m ... setting up hosts file.\e[0m"
    echo >> /etc/hosts "127.0.0.1 $(hostname) $fqdn"
    echo -e "\e[1;32m - set_hosts() finished"
    /usr/bin/logger 'set_hosts() finished' -t 'snipeit-2022-01-10';
}

rename_default_vhost() {
    /usr/bin/logger 'rename_default_vhost()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - rename_default_vhost()"
    echo -e "\e[1;36m ... enabling $APP_NAME site.\e[0m"
    mv /etc/apache2/sites-enabled/000-default.conf /etc/apache2/sites-enabled/111-default.conf > /dev/null 2>&1
    mv /etc/apache2/sites-enabled/snipeit.conf /etc/apache2/sites-enabled/000-snipeit.conf > /dev/null 2>&1
    echo -e "\e[1;32m - rename_default_vhost() finished"
    /usr/bin/logger 'rename_default_vhost() finished' -t 'snipeit-2022-01-10';
}

configure_permissions() {

    ######################################################
    #       Originally from the Snipe-It Install         #
    #          Script created by Mike Tucker             #
    #            mtucker6784@gmail.com                   #
    ######################################################
    
    /usr/bin/logger 'configure_permissions()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - configure_permissions()"
    echo -e "\e[1;36m ... setting permissions.\e[0m"
    for chmod_dir in "$APP_PATH/storage" "$APP_PATH/public/uploads"; do
        chmod -R 775 "$chmod_dir" > /dev/null 2>&1
    done
    chown -R "$APP_USER":"$apache_group" "$APP_PATH" > /dev/null 2>&1
    echo -e "\e[1;32m - configure_permissions()"
    /usr/bin/logger 'configure_permissions() finished' -t 'snipeit-2022-01-10';
}

run_composer() {
    
    ######################################################
    #       Originally from the Snipe-It Install         #
    #          Script created by Mike Tucker             #
    #            mtucker6784@gmail.com                   #
    ######################################################
    
    /usr/bin/logger 'run_composer()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - run_composer()"
    echo -e "\e[1;36m ... running composer."
    # We specify the path to composer because CentOS lacks /usr/local/bin in $PATH when using sudo
    sudo -i -u $APP_USER /usr/local/bin/composer install --no-dev --prefer-source --working-dir "$APP_PATH" > /dev/null 2>&1

    sudo chgrp -R "$apache_group" "$APP_PATH/vendor" > /dev/null 2>&1

    echo -e "\e[1;36m ... generating the application key.\e[0m"
    php $APP_PATH/artisan key:generate --force > /dev/null 2>&1

    echo -e "\e[1;36m ... artisan Migrate.\e[0m"
    php $APP_PATH/artisan migrate --force > /dev/null 2>&1

    echo -e "\e[1;36m ... creating scheduler cron.\e[0m"
    (crontab -l ; echo "* * * * * /usr/bin/php $APP_PATH/artisan schedule:run >> /dev/null 2>&1") | crontab -
    echo -e "\e[1;32m - run_composer() finished"
    /usr/bin/logger 'run_composer() finished' -t 'snipeit-2022-01-10';
}

install_pip_snipeit() {
    /usr/bin/logger 'install_pip_snipeit()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - install_pip_snipeit()"
    echo -e "\e[1;36m ... installing python pip module for Snipe-IT as $APP_USER.\e[0m"
    # https://github.com/jbloomer/SnipeIT-PythonAPI.git
    sudo -i -u $APP_USER python3 -m pip install snipeit
    echo -e "\e[1;32m - install_pip_snipeit() finished"
    /usr/bin/logger 'install_pip_snipeit() finished' -t 'snipeit-2022-01-10';
}

install_crowdsec() {
    /usr/bin/logger 'install_crowdsec()' -t 'Debian-FW-20211210';
    # Add repo
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash;
    #install crowdsec core daemon
    apt-get -y install crowdsec;
    # install firewall bouncer
    apt-get -y install crowdsec-firewall-bouncer-iptables;
    /usr/bin/logger 'install_crowdsec() finished' -t 'Debian-FW-20211210';
}

configure_crowdsec() {
    /usr/bin/logger 'configure_crowdsec()' -t 'Debian-FW-20211210';
    # Collection iptables
    cscli parsers install crowdsecurity/iptables-logs;
    cscli parsers install crowdsecurity/geoip-enrich;
    cscli scenarios install crowdsecurity/iptables-scan-multi_ports;
    cscli scenarios install crowdsecurity/ssh-bf;
    cscli collections install crowdsecurity/mysql;
    cscli collections install crowdsecurity/linux;
    cscli collections install crowdsecurity/iptables;
    cscli postoverflows install crowdsecurity/rdns;
    # Running 'sudo systemctl reload crowdsec' for the new configuration to be effective.
    systemctl reload crowdsec.service;
    # Enable auto complete for BASH
    source /etc/profile;
    source <(cscli completion bash);
    /usr/bin/logger 'configure_crowdsec() finished' -t 'Debian-FW-20211210';
}

configure_reverse_proxy() {
    /usr/bin/logger 'configure_reverse_proxy()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - configure_reverse_proxy()\e[0m"
    # Setting up reverse proxy config

    ######################################################
    #        Modified from the Snipe-It Install          #
    #          Script created by Mike Tucker             #
    #             Modified by Ryan Brooks                #
    ######################################################
    
    setupproxy=default
    until [[ $setupproxy == "yes" ]] || [[ $setupproxy == "no" ]]; do
    echo -e "\e[1;32m"
    echo -n "  Q. Do you want to configure reverse proxy settings? (y/n) "
    read -r setupproxy

    case $setupproxy in
    [yY] | [yY][Ee][Ss] )
        # Reverse proxy details
        # Server address or name
        echo -n " - IP address of the reverse proxy: "
        read -r proxyaddress
        sed -i "s|^\\(APP_TRUSTED_PROXIES=\\).*|\\1$proxyaddress|" "$APP_PATH/.env"
        # Create file to indicate reverse proxy is configured
        touch $proxyconfigFILE;
        setupproxy="yes"
        ;;
    [nN] | [n|N][O|o] )
        setupproxy="no"
        ;;
    *)  echo -e "\e[1;31m - Invalid answer. Please type y or n\e[0m"
        ;;
    esac
    done
    echo -e "\e[0m"
    /usr/bin/logger 'configure_reverse_proxy() finished' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - configure_reverse_proxy() finished\e[0m"
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    /usr/bin/logger 'Installing snipeit.......' -t 'snipeit';
    # Setting global vars
    #Prompt for email address instead of using a hardcoded address
    echo "Please enter your email address: "
    read mailaddress
    # CERT_TYPE can be Self-Signed or LetsEncrypt (internet connected, thus also installing crowdsec)
    readonly CERT_TYPE="Self-Signed"
    #Prompt for FQDN
    echo "Please enter the FQDN this application will be available at (such as snipeit.example.com):"
    read fqdn
    readonly HOSTNAME_ONLY="$(hostname --short)"
    # OS Version
    # freedesktop.org and systemd
    . /etc/os-release
    readonly OPERATING_SYSTEM=$NAME
    readonly VER=$VERSION_ID
    readonly codename=$VERSION_CODENAME
    # Snipe-IT App specific variables
    readonly APP_USER="snipeitapp"
    readonly APP_NAME="snipeit"
    readonly APP_PATH="/var/www/html/$APP_NAME"
    readonly mysqluserpw="$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16; echo)"
    readonly installedFILE="$APP_PATH/snipeit_installed";
    readonly mailconfigFILE="$APP_PATH/snipeit_mail"
    readonly proxyconfigFILE="$APP_PATH/snipeit_proxy"
    ## Variables required for certificate
    # organization name
    # (see also https://www.switch.ch/pki/participants/)
    readonly ORGNAME=snipeit_server
    # the fully qualified server (or service) name, change if other servicename than hostname
    # Local information
    readonly ISOCOUNTRY=DK;
    readonly PROVINCE=Denmark;
    readonly LOCALITY=Copenhagen
    # subjectAltName entries: to add DNS aliases to the CSR, delete
    # the '#' character in the ALTNAMES line, and change the subsequent
    # 'DNS:' entries accordingly. Please note: all DNS names must
    # resolve to the same IP address as the fqdn.
    readonly ALTNAMES=DNS:$HOSTNAME_ONLY # , DNS:bar.example.org , DNS:www.foo.example.org
    # Apache settings
    readonly APACHE_LOG_DIR=/var/log/apache2;
    readonly APACHE_DIR=/etc/apache2
    readonly APACHE_CERTS_DIR=$APACHE_DIR/certs
    readonly apache_group=www-data

    # Crowdsec to provide some additional awesome security for internet connected systems
    if ! [ -f $installedFILE -a -f $mailconfigFILE ];
    then
        /usr/bin/logger "Starting installation. Operating System $OPERATING_SYSTEM $VER $codename" -t 'snipeit-2022-01-10';
        echo -e "\e[1;32m - starting Snipe-IT installation on $fqdn"
        # Reveal OS, Version, and codename
        echo -e "\e[1;36m ... operating System $OPERATING_SYSTEM $VER $codename\e[0m";
        # install all required elements and generate certificates for webserver
        install_prerequisites;
        prepare_nix;
        create_user;

        install_snipeit;
        configure_permissions;
        install_composer;
        run_composer;
        configure_apache;
        rename_default_vhost;

        # Either generate a CSR and use with internal CA, create a self-signed certificate if you are running an internal test server
        # Or Use Lets Encrypt if this is a public server.
        # Configure CERT_TYPE above
        echo -e "\e[1;36m ... generating $CERT_SERVER certificate\e[0m"
        generate_certificates
        case $CERT_TYPE in
        LetsEncrypt)
            echo -e "\e[1;36m ... generating $CERT_SERVER certificate\e[0m"
            letsencrypt_certificates
            install_crowdsec;
            configure_crowdsec;
            ;;
        esac

        # Securing mariadb       
        mariadb_secure_installation;
        # Configuration of mail server require user input, so not working with Vagrant
        #configure_mail_server;
        configure_reverse_proxy;
        configure_permissions;
        install_pip_snipeit;
        show_databases;
        check_services;
        /usr/bin/logger 'snipeit Installation complete' -t 'snipeit-2022-01-10';
        echo -e;
        touch $installedFILE;
        echo -e "\e[1;32msnipeit Installation complete\e[0m";
        echo -e "\e[1;32m  *** Browse to \e[1;33mhttps://$fqdn \e[1;32mto login to Snipe-IT. ***\e[0m"
        echo -e "\e[1;32m* Cleaning up...\e[0m"
    else
        echo -e "\e[1;31m-------------------------------------------------------------------------------\e[0m";
        echo -e "\e[1;31m   It appears that snipeit Asset Server has already been installed\e[0m"
        echo -e "\e[1;31m   If this is in error, or you just want to install again, then delete the\e[0m"
        echo -e "\e[1;31m   files $installedFILE and $mailconfigfile & run this script again\e[0m"
        echo -e "\e[1;31m-------------------------------------------------------------------------------\e[0m";
    fi

    if [ -f $installedFILE -a ! -f $mailconfigFILE ];
    then
        echo -e "\e[1;31m-------------------------------------------------------------------------------\e[0m";
        echo -e "\e[1;31m   SnipeIT Asset Management Server has been installed, but mail not configured.\e[0m"
        echo -e "\e[1;31m           Please run the configure-mail.sh script to do this\e[0m"
        echo -e "\e[1;31m       If this install was based on Vagrant, remember to run the script\e[0m"
        echo -e "\e[1;31m        on the virtual guest $fqdn, not on the Virtual Host Server\e[0m"
        echo -e "\e[1;31m--------------------------------------------------------------------------------\e[0m";
    fi

    #rm -f install-snipe.sh > /dev/null 2>&1
    echo -e "\e[1;32m - Installation complete.\e[0m"
}

main;

exit 0;
