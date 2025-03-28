# 🚀 Installation Automatisée d'un Serveur Web L.A.M.P. sur Raspberry Pi

<p align="center">
  <img src="tux-server.jpg" alt="Admin Tux logo" width="600"/>
</p>

<p align="center">
  <a href="https://github.com/renaudgweb/server-install/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/Made%20with-Bash-1f425f.svg" alt="made-with-bash"></a>
</p>

Ce script Bash automatise l'installation d'un serveur Web sur un Raspberry Pi fonctionnant sous Raspberry Pi OS. Il installe L.A.M.P. (Linux, Apache, MySQL, PHP) ainsi que d'autres paquets, configure les paramètres de base et démarre les services, permettant ainsi aux utilisateurs d'héberger leurs propres sites Web. 🌍💻

## ✅ Prérequis

Assurez-vous d'avoir :
- Un Raspberry Pi fonctionnant sous Raspberry Pi OS 🖥️
- Une connexion Internet active 🌐

## 📌 Utilisation

1. **Ouvrez un terminal** sur votre Raspberry Pi. 🖥️
2. **Clonez ce dépôt GitHub** sur votre Raspberry Pi en utilisant la commande suivante :

   ```bash
   git clone https://github.com/renaudgweb/server-install.git
   ```

3. **Accédez au répertoire du dépôt** :

   ```bash
   cd server-install
   ```

4. **Donnez les permissions d'exécution au script** :

   ```bash
   sudo chmod +x install.sh
   ```

5. **Exécutez le script d'installation** :

   ```bash
   ./install.sh
   ```

6. **Suivez les instructions à l'écran** pour terminer le processus d'installation. ✅

📢 Une fois le script terminé, **Apache sera installé et configuré** sur votre Raspberry Pi. Vous pourrez accéder au serveur web en ouvrant un navigateur 🌐 et en entrant **l'adresse IP de votre Raspberry Pi** dans la barre d'adresse.

## ⚠️ Avertissement

Ce script est destiné à un **usage éducatif et de développement uniquement**. 🚧 Assurez-vous de comprendre les implications de sécurité avant d'héberger un site web accessible depuis Internet. Pour garantir la sécurité de votre Raspberry Pi :

- 🛠️ **Mettez à jour régulièrement** votre système d'exploitation et les logiciels installés.
- 🔒 **Appliquez des bonnes pratiques de sécurité** (pare-feu, mots de passe sécurisés, etc.).

---

**👤 Auteur :** Renaud G.  
**📌 Version :** 1.0
