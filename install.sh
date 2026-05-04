#!/usr/bin/env bash

#
# Script d'installation de paquets & configuration server Apache2
#

# Déclaration du fichier de log
LOGFILE="/home/"$USER"/install-server.log"
log_action() {
    local MESSAGE="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $MESSAGE" | sudo tee -a "$LOGFILE"
    logger "$MESSAGE"
}
# Capture toute la sortie du script (optionnel)
exec > >(tee -a "$LOGFILE") 2>&1

# Monter la clé USB
sudo mkdir -p /media/"$USER"/USB
sudo mount -t vfat /dev/sda1 /media/"$USER"/USB
BACKUP_ARCHIVE="/media/"$USER"/USB/backup.tar.gz"

# Vérifier si le script est exécuté avec les privilèges root
# if [ "$(id -u)" -ne 0 ]; then
# 	log_action "❌ Ce script doit être exécuté avec les privilèges root."
# 	echo "❌ Ce script doit être exécuté avec les privilèges root."
#     exit 1
# fi

# Quitte le programme si une commande échoue
set -o errexit
# Quitte le programme si variable non definie
set -o nounset
# Quitte le programme si une commande échoue dans un pipe
set -o pipefail

clear
cat << "EOF"
Renaud G.
Version : 1.0

			           _nnnn_
			          dGGGGMMb     ,""""""""""""""""""".
			         @p~qp~~qMb    | Linux🐧 Server🌐 |
			         M|@||@) M|   _;...................'
			         @,----.JM| -'
			        JS^\__/  qKL
			       dZP        qKRb
			      dZP      📦  qKKb
			     fZP       📥   SMMb
			     HZM            MMMM
			     FqM            MMMM
			   __| ".        |\dS"qML
			   |    `.       | `' \Zq
			  _)      \.___.,|     .'
			  \____   )MMMMMM|   .'
			       `-'       `--'

Installation de serveur LAMP    (/home/"$USER"/install-server.log)
/!\⚠️Bien penser à REBOOT après l'execution de ce script⚠️/!\

EOF

user_install() {
	# Ajouter un nouvel utilisateur
	read -p "Entre ton nouvel utilisateur : " USERNAME
    sudo adduser "$USERNAME"
    # Ajouter l'utilisateur aux sudoers directement
    echo "$USERNAME ALL=(ALL) ALL" | sudo tee -a /etc/sudoers.d/"$USERNAME"
    # Passer sur la session du nouvel utilisateur
    sudo su - "$USERNAME" -c "bash"
    # Supprimer l'utilisateur 'pi'
    sudo userdel -r pi
	log_action "user "$USERNAME" ajouté ✅️\n"
	echo "user "$USERNAME" ajouté ✅️\n"
}

usb_install() {
	# Récupérer le nom de la clé USB montée
	USB_KEY=/media/"$USER"/USB
	if [ -n "$USB_KEY" ]; then
	    log_action "Clé USB détectée."
	else
	    log_action "❌ Aucune clé USB détectée."
	    exit 1
	fi
	# Vérifier si l'archive existe
	if [ ! -f "$BACKUP_ARCHIVE" ]; then
	    log_action "❌ L'archive $BACKUP_ARCHIVE est introuvable !"
	    exit 1
	fi
	log_action "Récupération et extraction de l'archive USB"
	echo "Récupération et extraction de l'archive USB"
	# Répertoires archivés en ne mettant PAS le / devant.
	tar -xvzf "$BACKUP_ARCHIVE" -C / \
	    "home/"$USER"/Documents" \
	    "etc/default/keyboard" \
	    "etc/ssh/sshd_config" \
	    "var/www/html" \
	    "etc/init.d/firewall" \
	    "etc/hosts" \
	    "etc/hostname" \
	    "etc/apache2/apache2.conf" \
	    "etc/apache2/sites-available" \
	    "etc/apache2/mods-available/remoteip.conf" \
	    "etc/pam.d/sshd" \
	    "etc/ssmtp" \
	    "etc/fail2ban" \
	    "etc/portsentry/portsentry.conf" \
	    "etc/default/portsentry" \
	    "etc/rkhunter.conf" \
	    "etc/modsecurity/modsecurity.conf" \
	    "etc/apache2/conf.d/security" \
	    "etc/apache2/conf-available/security.conf" \
	    "etc/cron.daily/00logwatch" \
	    "etc/logwatch/conf/logwatch.conf" \
	    "etc/default/automysqlbackup" \
	    "etc/motd" \
	    "etc/clamav/clamd.conf" \
	    "etc/clamav/freshclam.conf" \
	    "etc/nftables.conf" \
	    "usr/local/bin/update-geoallow.sh" \
	    "usr/local/bin/nft-safe-reload.sh" \
	    "home/"$USER"/scriptBackup" \
	    "home/"$USER"/exeBackup.sh" \
	    "home/"$USER"/.bashrc" \
	    "home/"$USER"/.bash_history"
	log_action "Les repertoires /etc sont installés ✅️\n"
	echo "Les repertoires /etc sont installés ✅️\n"

	# Appliquer les modifications pour le keyboard
	sudo setupcon
	sudo systemctl restart ssh
	log_action "modifications pour le keyboard installés ✅️\n"
	echo "modifications pour le keyboard installés ✅️\n"
}

iptable_install() {
	# Donner les bonnes permissions au fichier
	sudo chmod +x /etc/init.d/firewall
	# Ajouter le script au démarrage du système
	sudo update-rc.d firewall defaults
	log_action "Iptable Installé ✅️\n"
	echo "Iptable Installé ✅️\n"
}

apt_install() {
	sudo wget -qO /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
	echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/php.list
	sudo apt update && sudo apt upgrade
	log_action "Les paquets APT sont à jour ✅️\n"
	echo "Les paquets APT sont à jour ✅️\n"

	packages_apt="apache2 \
		          libapache2-mod-security2 \
		          libapache2-mod-evasive \
		          ntp \
		          ntpdate \
		          modsecurity-crs \
		          libpam-tmpdir \
		          lynis \
		          rkhunter \
		          portsentry \
		          fail2ban \
		          ssmtp \
		          mariadb-server \
		          wondershaper \
		          clamav \
		          clamav-daemon \
		          autoconf \
		          libtool \
		          automake \
		          automysqlbackup \
		          ccze \
		          php8.4 \
		          php8.4-cli
		          php8.4-fpm \
		          php8.4-opcache \
		          php8.4-curl \
		          php8.4-mbstring \
		          php8.4-zip \
		          php8.4-xml \
		          php8.4-gd \
		          php8.4-bcmath \
		          php8.4-apcu \
		          php8.4-redis \
		          php8.4-mysql \
		          php8.4-mcrypt \
		          php8.4-imagick \
		          php8.4-intl \
		          php8.4-json \
		          libapache2-mod-php8.4 \
		          libapache2-mod-fcgid \
		          apt-transport-https \
		          ca-certificates \
		          bmon \
		          htop \
		          logwatch \
		          ntpdate \
		          redis-server \
		          build-essential \
		          python3-pip \
		          clamav \
		          clamav-daemon \
		          expect \
		          phpmyadmin \
		          wget \
		          curl \
		          unzip \
		          ufw \
		          mailx \
		          debootstrap"

	# Installation des paquets APT
	sudo apt install $packages_apt -y
	if [ $? -ne 0 ]; then
		log_action "Erreur lors de l'installation des paquets APT"
	    echo "Erreur lors de l'installation des paquets APT"
	    exit 1
	fi
	log_action "Les paquets APT sont installés ✅️\n"
	echo "Les paquets APT sont installés ✅️\n"
}

wiringpi_install() {
	# Ajout de lib pour TM1637
	pip install wiringpi
	log_action "wiringpi Installé ✅️\n"
	echo "wiringpi Installé ✅️\n"
}

a2_install() {
	# Demarrage des services Apache2 et MariaDb au démarrage
	sudo systemctl start apache2 && sudo systemctl enable apache2
	sudo systemctl start mariadb && sudo systemctl enable mariadb
	log_action "Les services Apache et MariaDb sont demarrer et activés ✅️\n"
	echo "Les services Apache et MariaDb sont demarrer et activés ✅️\n"
}

wondershaper_install() {
	sudo systemctl start wondershaper && sudo systemctl enable wondershaper
	log_action "Le service Wondershaper est demarré et activé ✅️\n"
	echo "Le service Wondershaper est demarré et activé ✅️\n"
}

mysql_install() {
    # Installation sécurisée de MariaDB avec expect
    echo "Sécurisation de MariaDB..."
    read -s -p "Entrez le mot de passe root pour MariaDB : " root_password
    echo
    read -p "Entrez le nom du nouvel utilisateur : " new_user
    read -s -p "Entrez le mot de passe pour le nouvel utilisateur : " new_user_password
    echo
    read -p "Entrez le nom de la base de données : " database_name
    # Script expect pour automatiser mysql_secure_installation
    expect <<EOF
spawn sudo mysql_secure_installation
expect "Enter current password for root (enter for none):"
send "\n"
expect "Set root password?"
send "Y\n"
expect "New password:"
send "$root_password\n"
expect "Re-enter new password:"
send "$root_password\n"
expect "Remove anonymous users?"
send "Y\n"
expect "Disallow root login remotely?"
send "Y\n"
expect "Remove test database and access to it?"
send "Y\n"
expect "Reload privilege tables now?"
send "Y\n"
expect eof
EOF
    log_action "Création de la base de données et de l'utilisateur..."
    echo "Création de la base de données et de l'utilisateur..."
    sudo mysql -u root -p"$root_password" <<MYSQL_SCRIPT
CREATE DATABASE IF NOT EXISTS \`$database_name\`;
CREATE USER IF NOT EXISTS '$new_user'@'localhost' IDENTIFIED BY '$new_user_password';
GRANT ALL PRIVILEGES ON \`$database_name\`.* TO '$new_user'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

    sudo systemctl restart mariadb
    log_action "MySQL Installé et sécurisé ✅️\n"
    echo "MySQL Installé et sécurisé ✅️\n"
}

phpmyadmin_install() {
	sudo apt install phpmyadmin
	sudo ln -s /usr/share/phpmyadmin /var/www/html/renaud/phpmyadmin
	# Répertoires archivés en ne mettant PAS le / devant.
	tar -xvzf "$BACKUP_ARCHIVE" -C / "etc/phpmyadmin/.htpasswd"
	log_action "PhpMyAdmin Installé ✅️\n"
	echo "PhpMyAdmin Installé ✅️\n"
}

modsecurity_install() {
	echo -e "\n<IfModule security2_module>" | sudo tee -a /etc/apache2/apache2.conf
	echo "    IncludeOptional /etc/modsecurity/*.conf" | sudo tee -a /etc/apache2/apache2.conf
	echo "    IncludeOptional /etc/modsecurity/rules/*.conf" | sudo tee -a /etc/apache2/apache2.conf
	echo "</IfModule>" | sudo tee -a /etc/apache2/apache2.conf
	log_action "Modsecurity Installé ✅️\n"
	echo "Modsecurity Installé ✅️\n"
}

modsecurity_crs_install() {
	sudo a2enconf security
	sudo ln -s /usr/share/modsecurity-crs/crs-setup.conf /etc/modsecurity/crs-setup.conf
	sudo ln -s /usr/share/modsecurity-crs/rules/*.conf /etc/modsecurity/rules/
	log_action "Modsecurity crs Installé ✅️\n"
	echo "Modsecurity crs Installé ✅️\n"
}

fpm_php_install() {
	PHP_INI_FILE="/etc/php/8.4/fpm/php.ini"
	# Fonction pour remplacer ou ajouter une ligne dans php.ini
	update_php_ini() {
	    local param=$1
	    local value=$2
	    # Remplacer la ligne si elle existe (commentée ou non)
	    sed -i "s|^ *;*\($param\)=.*|\1=$value|" "$PHP_INI_FILE"
	    # Ajouter la ligne si elle n'existe pas
	    grep -q "^$param=" "$PHP_INI_FILE" || echo "$param=$value" >> "$PHP_INI_FILE"
	}
	# Mettre à jour les paramètres
	update_php_ini "opcache.enable" "1"
	update_php_ini "opcache.enable_cli" "1"
	update_php_ini "opcache.memory_consumption" "128"
	update_php_ini "opcache.interned_strings_buffer" "8"
	update_php_ini "opcache.max_accelerated_files" "10000"
	update_php_ini "opcache.revalidate_freq" "1"
	update_php_ini "opcache.save_comments" "1"
	log_action "Le fichier php.ini a été mis à jour avec les nouveaux paramètres."
	echo "Le fichier php.ini a été mis à jour avec les nouveaux paramètres."
	sudo systemctl restart php8.4-fpm.service
	log_action "fpmPHP Installé ✅️\n"
	echo "fpmPHP Installé ✅️\n"
}

php_install() {
	PHP_INI_FILES=("/etc/php/8.4/apache2/php.ini" "/etc/php/8.4/cli/php.ini")
	# Fonction pour remplacer ou ajouter une ligne dans php.ini
	update_php_ini() {
	    local file=$1
	    local param=$2
	    local value=$3
	    # Remplacer la ligne si elle existe (commentée ou non)
	    sed -i "s|^ *;*\($param\)=.*|\1=$value|" "$file"
	    # Ajouter la ligne si elle n'existe pas
	    grep -q "^$param=" "$file" || echo "$param=$value" >> "$file"
	}
	# Mettre à jour les paramètres dans chaque fichier
	for PHP_INI_FILE in "${PHP_INI_FILES[@]}"; do
	    update_php_ini "$PHP_INI_FILE" "opcache.memory_consumption" "256"
	    update_php_ini "$PHP_INI_FILE" "opcache.interned_strings_buffer" "32"
	done
	log_action "Les fichiers php.ini ont été mis à jour avec les nouveaux paramètres."
	echo "Les fichiers php.ini ont été mis à jour avec les nouveaux paramètres."
	sudo a2ensite renaud
	sudo a2ensite default-ssl
	sudo a2enmod ssl
	sudo a2enmod headers
	sudo a2enmod env
	sudo a2enmod dir
	sudo a2enmod mime
	sudo a2enmod rewrite
	sudo a2enmod setenvif
	sudo a2enmod proxy_fcgi
	sudo a2enmod remoteip
	sudo a2enmod evasive
	sudo a2enconf php8.4-fpm
	sudo chown -R "$USER":www-data /var/www/html/

	sudo systemctl restart apache2
	log_action "Service apache2 sont redemarrés ✅️\n"
	echo "Service apache2 sont redemarrés ✅️\n"
	log_action "PHP Installé ✅️\n"
	echo "PHP Installé ✅️\n"
}

ufw_install() {
	# Activer le pare-feu
	sudo ufw allow 4446/tcp
	sudo ufw allow 80,443/tcp
	sudo ufw allow out 587/tcp
	sudo ufw enable
	log_action "UFW Installé ✅️\n"
	echo "UFW Installé ✅️\n"
}

security_install() {
	# -------------------------
	# Mises à jour automatiques
	# -------------------------
	sudo apt install unattended-upgrades apt-listchanges -y
	# Active les mises à jour automatiques sans interaction (remplace le dpkg-reconfigure interactif)
	echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | \
	    sudo debconf-set-selections
	sudo dpkg-reconfigure -f noninteractive unattended-upgrades
	log_action "Unattended-upgrades Installé ✅️\n"
	echo "Unattended-upgrades Installé ✅️\n"

	# --------
	# nftables
	# --------
	sudo apt install nftables -y
	sudo systemctl enable nftables
	sudo systemctl start nftables
	log_action "nftables Installé et démarré ✅️\n"
	echo "nftables Installé et démarré ✅️\n"

	# --------
	# CrowdSec
	# --------
	curl -s https://install.crowdsec.net | sudo sh
	sudo apt install crowdsec crowdsec-firewall-bouncer-nftables -y
	sudo systemctl enable crowdsec
	sudo systemctl enable crowdsec-firewall-bouncer
	sudo systemctl start crowdsec
	sudo systemctl start crowdsec-firewall-bouncer
	# Collections de règles CrowdSec
	sudo cscli collections install crowdsecurity/sshd
	sudo cscli collections install crowdsecurity/apache2
	sudo systemctl restart crowdsec
	log_action "CrowdSec Installé ✅️\n"
	echo "CrowdSec Installé ✅️\n"

	# ---------------------
	# GeoAllow & nft-reload
	# ---------------------
	# Les scripts doivent être présents dans l'archive USB (extraits par usb_install)
	sudo chmod +x /usr/local/bin/update-geoallow.sh
	sudo /usr/local/bin/update-geoallow.sh
	sudo chmod +x /usr/local/bin/nft-safe-reload.sh
	sudo nft -f /etc/nftables.conf
	log_action "GeoAllow et nft-safe-reload configurés ✅️\n"
	echo "GeoAllow et nft-safe-reload configurés ✅️\n"
}

sendmail_install() {
	sudo chmod 644 /etc/ssmtp/ssmtp.conf
	sudo chown root:mail /usr/sbin/ssmtp /etc/ssmtp{,/{ssmtp.conf,revaliases}}
	sudo chmod 2711 /usr/sbin/ssmtp
	sudo chmod o-rwx /etc/ssmtp /etc/ssmtp/ssmtp.conf; # 0750, 0640
	sudo dpkg-statoverride --add root mail 2711 /usr/sbin/ssmtp
	sudo dpkg-statoverride --add root mail 0750 /etc/ssmtp
	sudo dpkg-statoverride --add root mail 0640 /etc/ssmtp/ssmtp.conf
	sudo dpkg-statoverride --add root mail 0644 /etc/ssmtp/revaliases
	log_action "SendMail Installé ✅️\n"
	echo "SendMail Installé ✅️\n"
}

fail2ban_install() {
	fail2ban-regex /var/log/apache2/phpmyadmin-access.log /etc/fail2ban/filter.d/phpmyadmin.conf
	sudo systemctl restart fail2ban
	log_action "Fail2Ban Installé ✅️\n"
	echo "Fail2Ban Installé ✅️\n"
}

portsentry_install() {
	sudo service portsentry restart
	log_action "Portsentry Installé ✅️\n"
	echo "Portsentry Installé ✅️\n"
}

rkhunter_install() {
	sudo rkhunter --update
	sudo rkhunter --propupdate
	log_action "RKHunter Installé ✅️\n"
	echo "RKHunter Installé ✅️\n"
}

logwatch_install() {
	sudo mkdir /var/cache/logwatch
	log_action "Logwatch Installé ✅️\n"
	echo "Logwatch Installé ✅️\n"
}

nextcloud_install() {
	cd /home/"$USER"
	wget https://download.nextcloud.com/server/releases/latest.zip
	wget https://download.nextcloud.com/server/releases/latest.zip.sha256
	# Vérifier l'intégrité du fichier téléchargé
	if sha256sum -c latest.zip.sha256 --quiet; then
		log_action "Vérification de l'intégrité réussie ✅️"
		echo "Vérification de l'intégrité réussie ✅️"
	else
		log_action "Erreur de vérification du fichier. Le téléchargement ou le fichier est corrompu ❌"
		echo "Erreur de vérification du fichier. Le téléchargement ou le fichier est corrompu ❌"
		exit 1
	fi
	unzip latest.zip
	sudo cp -rv latest /var/www/html/
	mv latest nextcloud
	sudo chown www-data:www-data /var/www/html/nextcloud/ -Rv
	tar -xvzf "$BACKUP_ARCHIVE" -C / "home/"$USER"/datanextcloud" "var/www/html/nextcloud/config/config.php"
	sudo chown www-data:www-data /home/"$USER"/datanextcloud
	sudo chown www-data:www-data var/www/html/nextcloud/config/config.php
	log_action "Nextcloud Installé ✅️\n"
	echo "Nextcloud Installé ✅️\n"
}

certbot_install() {
	cd /home/"$USER" && wget https://dl.eff.org/certbot-auto
	sudo chmod a+x certbot-auto
	sudo ./certbot-auto
	sudo certbot renew --rsa-key-size 4096 --force-renewal
	log_action "Certbot Installé ✅️\n"
	echo "Certbot Installé ✅️\n"
}

clamav_install() {
	sudo freshclam
	sudo systemctl start clamav-daemon && sudo systemctl enable clamav-daemon
	log_action "ClamAV Installé ✅️\n"
	echo "ClamAV Installé ✅️\n"
}

automysqlbackup_install() {
	mkdir /home/"$USER"/automysqlbackup
	sudo cp /media/"$USER"/USB/automysqlbackup/ /home/"$USER"/automysqlbackup/
	log_action "AutoMySQLBackup Installé ✅️\n"
	echo "AutoMySQLBackup Installé ✅️\n"
}

matomo_install() {
	wget https://builds.matomo.org/matomo.zip && unzip matomo.zip -d /var/www/html/renaud
	git clone --recursive https://github.com/maxmind/libmaxminddb
	cd libmaxminddb && ./bootstrap
	wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
	sudo mv GeoLite2-City.mmdb /var/www/html/renaud/matomo/misc/
	log_action "Matomo Installé ✅️\n"
	echo "Matomo Installé ✅️\n"
}

phpsysinfo_install() {
	# Définition des variables
	INSTALL_DIR="/var/www/html/renaud/phpsysinfo"
	TMP_DIR="/tmp/phpsysinfo_install"
	ARCHIVE_NAME="phpsysinfo.tar.gz"
	# Création du répertoire temporaire
	mkdir -p "$TMP_DIR"
	cd "$TMP_DIR"
	# Récupération du lien de téléchargement de la dernière version
	TARBALL_URL=$(curl -s https://api.github.com/repos/phpsysinfo/phpsysinfo/releases/latest | grep '"tarball_url"' | cut -d '"' -f 4)
	# Vérification si l'URL est bien récupérée
	if [[ -z "$TARBALL_URL" ]]; then
		log_action "Erreur : Impossible de récupérer le lien de téléchargement."
	    echo "Erreur : Impossible de récupérer le lien de téléchargement."
	    exit 1
	fi
	# Téléchargement de l'archive
	log_action "Téléchargement de phpsysinfo..."
	echo "Téléchargement de phpsysinfo..."
	wget -q "$TARBALL_URL" -O "$ARCHIVE_NAME"
	# Suppression de l'ancienne installation si elle existe
	if [[ -d "$INSTALL_DIR" ]]; then
		log_action "Suppression de l'ancienne installation..."
	    echo "Suppression de l'ancienne installation..."
	    rm -rf "$INSTALL_DIR"
	fi
	# Extraction de l'archive
	log_action "Extraction de l'archive..."
	echo "Extraction de l'archive..."
	tar -xzf "$ARCHIVE_NAME"
	# Trouver le dossier extrait (qui a un nom dynamique)
	EXTRACTED_DIR=$(ls -d phpsysinfo-*/ 2>/dev/null | head -n 1)
	# Vérification si l'extraction s'est bien déroulée
	if [[ -z "$EXTRACTED_DIR" ]]; then
		log_action "Erreur : Impossible de trouver le dossier extrait."
	    echo "Erreur : Impossible de trouver le dossier extrait."
	    exit 1
	fi
	# Déplacement vers le répertoire d'installation
	mv "$EXTRACTED_DIR" "$INSTALL_DIR"
	# Nettoyage des fichiers temporaires
	rm -rf "$TMP_DIR"
	# Attribution des permissions correctes
	log_action "Configuration des permissions..."
	echo "Configuration des permissions..."
	chown -R www-data:www-data "$INSTALL_DIR"
	chmod -R 755 "$INSTALL_DIR"
	log_action "PHPSysInfo installé ✅️\n"
	echo "PHPSysInfo installé ✅️\n"
}

rpiclone_install() {
	cd /home/"$USER" && git clone https://github.com/billw2/rpi-clone.git
	cd rpi-clone
	sudo cp rpi-clone rpi-clone-setup /usr/local/sbin
	log_action "RPI Clone installé ✅️\n"
	echo "RPI Clone installé ✅️\n"
}

logianalyzer_install() {
	cd /home/"$USER" && git clone https://github.com/renaudgweb/LogIAnalyzer.git
	cd LogIAnalyzer
	pip install -r requirements.txt
	read -p "Entrez les chemins des fichiers logs (séparés par des virgules) : " log_files
	read -p "Entrez l'adresse email de l'expéditeur : " email_sender
	read -p "Entrez l'adresse email du destinataire : " email_receiver
	read -p "Entrez le serveur SMTP : " smtp_server
	cat > "config.ini" <<EOL
[Settings]
log_files = $log_files
email_sender = $email_sender
email_receiver = $email_receiver
smtp_server = $smtp_server
smtp_port = 587
log_check_interval = 300
ai_temperature = 0.5
ai_max_tokens = 4096
daily_report_file = /var/log/log_analyzer_daily_report.txt
EOL
	read -p "Entrez la clé API IA : " ai_api_key
	read -p "Entrez le mot de passe SMTP : " smtp_password
	touch .env
	echo "AI_API_KEY=$ai_api_key" > .env
	echo "SMTP_PASSWORD=$smtp_password" > .env
	sudo chmod 600 .env
	sudo touch /etc/systemd/system/logianalyzer.service
	sudo tee /etc/systemd/system/logianalyzer.service > /dev/null <<EOL
[Unit]
Description=Surveillance des logs avec IA
After=network.target

[Service]
User=root
ExecStart=/usr/bin/python3 /home/"$USER"/LogIAnalyzer/logianalyzer.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL
	sudo systemctl daemon-reload
	sudo systemctl enable logianalyzer
	sudo systemctl start logianalyzer
	log_action "LogIAnalyzer installé ✅️\n"
	echo "LogIAnalyzer installé ✅️\n"
}

crontab_install() {
	# Obtient le contenu du crontab de l'utilisateur courant s'il existe, sinon crée un fichier vide
	sudo -u "$USER" crontab -l > crontab_temp 2>/dev/null || touch crontab_temp
	{
		echo ""
		echo "SHELL=/bin/bash"

		echo "# Reboot Notification via Nextcloud Talk"
		echo "@reboot /home/"$USER"/Documents/nextcloudBot/./reboot.sh"

		echo "# CPU high usage Notification (every 5min)"
		echo "*/5 * * * * /home/"$USER"/Documents/nextcloudBot/./cpu.sh"

		echo "# RAM Memory high usage Notification (every 5min)"
		echo "*/5 * * * * /home/"$USER"/Documents/nextcloudBot/./free.sh"

		echo "# Disk space high usage Notification"
		echo "@daily /home/"$USER"/Documents/nextcloudBot/./disk.sh"

		echo "# Temperature high usage Notification (every 5min)"
		echo "*/5 * * * * /home/"$USER"/Documents/nextcloudBot/./temp.sh"

		echo "# Weather NC Talk Bot Notification (All days at 08:35am)"
		echo "35 8 * * * /home/"$USER"/Documents/nextcloudBot/./weather.sh"

		echo "# Random ISS, ChuckNorris, Weather Notification (all Saturday @ random time of 2h after 18h)"
		echo "0 18 * * 6 sleep \$(( RANDOM \% 7200 )); /home/"$USER"/Documents/nextcloudBot/./random.sh"
	} >> crontab_temp
	# Installe la nouvelle crontab pour l'utilisateur actuel
	if sudo -u "$USER" crontab crontab_temp; then
		rm crontab_temp
		log_action "Cron is installed successfully ✔️\n"
		echo "Cron is installed successfully ✔️\n"
	else
		log_action "Error during cron installation ❌"
		echo "Error during cron installation ❌"
		rm crontab_temp
		exit 1
	fi

	read -p "Entrez l'adresse email du destinataire de log RPI Clone : " email_receiver
  	# sudo crontab
	# Obtient le contenu du crontab de root s'il existe, sinon crée un fichier vide
	sudo crontab -u root -l > crontab_temp 2>/dev/null || touch crontab_temp
	# Ajoute les nouvelles lignes à la fin du fichier temporaire
	{
		echo "# script de sauvegarde du lundi au dimanche à 05h00"
		echo "00 05 * * 1-7 /home/"$USER"/exeBackup.sh"

		echo "# script de sauvegarde de base de données MariaDB quotidien"
		echo "00 04 * * 1-7 /usr/sbin/automysqlbackup"

		echo "# script de renouvelement certificat SSL 1 fois par mois"
		echo "@monthly certbot renew --rsa-key-size 4096 --force-renewal"

		echo "# Script affichage Temperature CPU sur TM1637 au redemarrage"
		echo "@reboot python3 /home/"$USER"/Documents/tm1637/cpuTemp.py"

		echo "# Disable WiFi"
		echo "@reboot ifconfig wlan0 down"

		echo "# Start Wondershaper"
		echo "@reboot wondershaper -a eth0 -d 4096 -u 8192"

		echo "# Maj paquets apt tous les jours à 3h du matin"
		echo "0 3 * * * /usr/bin/apt update && /usr/bin/apt upgrade -y"

		echo "# RPI Clone tous les lundis à 02h00 du matin"
		echo "0 2 * * 1 echo \"yes\" | rpi-clone sdb -v > /var/log/rpi-clone.log 2>&1 && mailx -s \"RPi Clone Log\" "$email_receiver" < /var/log/rpi-clone.log"

		echo "# Nextcloud crontab"
		echo "*/5 * * * * su -s /bin/sh -c \"php -f /var/www/html/nextcloud/cron.php --define apc.enable_cli=1\" www-data > /home/"$USER"/CRON.txt 2>&1"

		echo "# Mise à jour GeoAllow + rechargement nftables tous les lundis à 04h00"
		echo "0 4 * * 1 /usr/local/bin/update-geoallow.sh && /usr/local/bin/nft-safe-reload.sh"
	} >> crontab_temp
	# Installe la nouvelle crontab pour root
	if sudo crontab -u root crontab_temp; then
		rm crontab_temp
		log_action "Cron is installed successfully ✔️\n"
		echo "Cron is installed successfully ✔️\n"
	else
		log_action "Error during cron installation ❌"
		echo "Error during cron installation ❌"
		rm crontab_temp
		exit 1
	fi
}

main_install() {
	#user_install
	usb_install
	iptable_install
	apt_install
	wiringpi_install
	a2_install
	wondershaper_install
	mysql_install
	phpmyadmin_install
	modsecurity_install
	modsecurity_crs_install
	fpm_php_install
	php_install
	ufw_install
	security_install
	sendmail_install
	fail2ban_install
	portsentry_install
	rkhunter_install
	logwatch_install
	nextcloud_install
	certbot_install
	clamav_install
	automysqlbackup_install
	matomo_install
	phpsysinfo_install
	rpiclone_install
	logianalyzer_install
	crontab_install

	sudo apt update && sudo apt -y autoremove && sudo apt -y clean
	log_action "Les mises à jour sont installés ✅️\n"
	echo "Les mises à jour sont installés ✅️\n"
}

prompt_choice() {
    local prompt=$1
    local choice
    while true; do
        echo "$prompt"
        read -r choice
        case $choice in
            [Yy]* ) return 0;;
            [Nn]* ) echo "Bye 👋"; exit;;
            * ) echo "⛔️Entrez Y ou N";;
        esac
    done
}

# Demande initiale pour commencer l'installation
prompt_choice "Voulez-vous continuer ? [Y]es✔️, ou [N]o❌ : " && main_install

# Message rappelant les tâches manuelles avec couleur
printf "\e[31m⚠️ Rappel ⚠️\e[0m\n  \e[33m- Restaurer la base de données\n  - Changer l'ID du bot Nextcloud\e[0m\n"

while true; do
    printf "\e[32mInstallation terminée 🚀 [R]ebooter ou [Q]uitter ?\e[0m\n"
    read -r REPLY
    case $REPLY in
        [Rr]* ) sudo reboot; break;;
        [Qq]* ) echo "Bye 👋"; exit;;
        * ) echo "⛔️Entrez R ou Q";;
    esac
done
