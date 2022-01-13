#! /bin/bash

#############################################################################
#                                                                           #
# Author:       Martin Boller                                               #
#                                                                           #
# Email:        martin@bollers.dk                                           #
# Last Update:  2022-01-09                                                  #
# Version:      1.00                                                        #
#                                                                           #
# Changes:      Initial Version (1.00)                                      #
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
    /usr/bin/logger 'configure_mail_server()' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - configure_mail_server()\e[0m"
    echo -e "\e[1;32m"
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
    echo -n " - Username: "
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
    echo -n " - From address: "
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
    touch $mailconfigFILE;
    /usr/bin/logger 'configure_mail_server() finished' -t 'snipeit-2022-01-10';
    echo -e "\e[1;32m - configure_mail_server() finished\e[0m"
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    /usr/bin/logger 'Installing snipeit.......' -t 'snipeit';
    # Setting global vars
    # the fully qualified server (or service) name, change if other servicename than hostname
    readonly fqdn="$(hostname --fqdn)"# OS Version
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


    # Apache settings
    readonly APACHE_LOG_DIR=/var/log/apache2;
    readonly APACHE_DIR=/etc/apache2
    readonly APACHE_CERTS_DIR=$APACHE_DIR/certs
    readonly apache_group=www-data

    if [ -f $installedFILE -a ! -f $mailconfigFILE ] ;
    then
        /usr/bin/logger "Starting configuration of mail. Operating System $OPERATING_SYSTEM $VER $codename" -t 'snipeit-2022-01-10';
        echo -e "\e[1;32m - starting Snipe-IT e-mail configuration on $fqdn"
        # Configuration of mail server.
        configure_mail_server;
        /usr/bin/logger 'mail configuration complete' -t 'snipeit-2022-01-10';
        echo -e;
        echo -e "\e[1;32m - snipeit mail configuration complete\e[0m";
        echo -e "\e[1;32m  *** Browse to \e[1;33mhttps://$fqdn \e[1;32mto login to Snipe-IT. ***\e[0m"
        echo -e "\e[1;32m* Cleaning up...\e[0m"
        rm -f configure-mail.sh > /dev/null 2>&1
    else
        echo -e "\e[1;31m---------------------------------------------------------------------\e[0m";
        echo -e "\e[1;31m   It appears that snipeit Asset Server has already been setup\e[0m"
        echo -e "\e[1;31m   and mail configured on the server. If this is in error\e[0m"
        echo -e "\e[1;31m   delete the file $mailconfigFILE and run this script again\e[0m"
        echo -e "\e[1;31m---------------------------------------------------------------------\e[0m";
    fi

    echo -e "\e[1;32m - Installation complete.\e[0m"

}

main;

exit 0;
