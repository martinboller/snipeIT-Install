#! /bin/bash

#####################################################################
#                                                                   #
# Author:       Martin Boller                                       #
#                                                                   #
# Email:        martin                                              #
# Last Update:  2022-01-09                                          #
# Version:      1.00                                                #
#                                                                   #
# Changes:      First version for snipeit (1.00)                    #
#                                                                   #
#                                                                   #
#####################################################################

configure_locale() {
  /usr/bin/logger 'configure_locale()' -t 'snipeit';
  echo -e "\e[32m - configure_locale()\e[0m";
  echo -e "\e[36m ... configuring locale (default:C.UTF-8)\e[0m";
  export DEBIAN_FRONTEND=noninteractive;
  cat << __EOF__  > /etc/default/locale
# /etc/default/locale
LANG=C.UTF-8
LANGUAGE=C.UTF-8
LC_ALL=C.UTF-8
__EOF__
  echo -e "\e[36m ... updating locale (default:C.UTF-8)\e[0m";
  update-locale > /dev/null 2>&1;
  echo -e "\e[32m - configure_locale() finished\e[0m";
  /usr/bin/logger 'configure_locale() finished' -t 'snipeit';
}

configure_timezone() {
  /usr/bin/logger 'configure_timezone()' -t 'snipeit';
  echo -e "\e[32m - configure_timezone()\e[0m";
  echo -e "\e[36m ... Setting timezone to Etc/UTC\e[0m";
  export DEBIAN_FRONTEND=noninteractive;
  rm /etc/localtime > /dev/null 2>&1;
  echo 'Etc/UTC' > /etc/timezone;
  dpkg-reconfigure -f noninteractive tzdata > /dev/null 2>&1;
  echo -e "\e[32m - configure_timezone() finished\e[0m";
  /usr/bin/logger 'configure_timezone() finished' -t 'snipeit';
}

bootstrap_prerequisites() {
  # Install prerequisites and useful tools
  /usr/bin/logger 'bootstrap_prerequisites()' -t 'snipeit';
  echo -e "\e[32m - bootstrap_prerequisites()\e[0m";
  export DEBIAN_FRONTEND=noninteractive;
  echo -e "\e[36m ... removing unwanted packages installed on the vagrant box\e[0m";
  apt-get -qq -y remove postfix* memcached > /dev/null 2>&1;
  sync
  echo -e "\e[36m ... updating packages\e[0m";  
  apt-get -qq update > /dev/null 2>&1
  apt-get -qq -y full-upgrade > /dev/null 2>&1
  echo -e "\e[36m ... cleaning up apt\e[0m";  
  apt-get -qq -y --purge autoremove > /dev/null 2>&1
  apt-get -qq autoclean > /dev/null 2>&1
  sync;
  echo -e "\e[36m ... removing weird nameserver from interfaces file\e[0m";  
  sed -i '/dns-nameserver/d' /etc/network/interfaces > /dev/null 2>&1;
  ifdown eth0 > /dev/null 2>&1; ifup eth0 > /dev/null 2>&1;
  # copy relevant scripts
  echo -e "\e[36m ... copying relevant installation scripts and settings correct permissions\e[0m";  
  /bin/cp /tmp/installfiles/* /root/ > /dev/null 2>&1;
  chmod 744 /root/*.sh > /dev/null 2>&1;
  echo -e "\e[32m - bootstrap_prerequisites() finished\e[0m";
  /usr/bin/logger 'bootstrap_prerequisites() finished' -t 'snipeit';
}

public_ssh_keys() {
  # Echo add SSH public key for root logon
  echo -e "\e[32m - adding public ssh key\e[0m";
  export DEBIAN_FRONTEND=noninteractive;
  mkdir /root/.ssh > /dev/null 2>&1;
  echo -e "\e[36m ... adding key to authorized_keys file\e[0m";  
  echo  $PublicSSHKey |  tee -a /root/.ssh/authorized_keys > /dev/null 2>&1;
  echo -e "\e[36m ... setting permissions on authorized_keys file\e[0m";  
  chmod 700 /root/.ssh > /dev/null 2>&1;
  chmod 600 /root/.ssh/authorized_keys > /dev/null 2>&1;
  echo -e "\e[32m - adding public ssh key finished\e[0m";
  /usr/bin/logger 'public_ssh_keys()' -t 'snipeit';
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
  echo -e "\e[32m - bootstrap main()\e[0m";
  clear
  #change domain below
  #readonly DOMAINNAME=bollers.dk;
  # Do not forget to remove my test public key and add your own public SSH Key(s) below
  readonly PublicSSHKey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIHJYsxpawSLfmIAZTPWdWe2xLAH758JjNs5/Z2pPWYm"
  /usr/bin/logger '!!!!! Main routine starting' -t 'snipeit';
  #hostnamectl set-hostname $HOSTNAME.$DOMAINNAME > /dev/null 2>&1;
  public_ssh_keys;
  configure_timezone;
  bootstrap_prerequisites;
  configure_locale;
  if [ "$HOSTNAME" = "simo" ];
  then
    echo -e "\e[1;32m - Installing Snipe-IT Asset Management Server $HOSTNAME\e[0m";
    /root/install-snipe.sh;
  fi
  echo -e "\e[32m - bootstrap main() finished\e[0m";
  /usr/bin/logger 'installation finished (Main routine finished)' -t 'snipeit'; 
}

main;

exit 0
