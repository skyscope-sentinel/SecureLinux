#!/bin/bash

# Set up terminal colors
GREEN='\033[1;32m'
NC='\033[0m'

# Display header
clear
echo -e "${GREEN}"
echo "Skyscope Sentinel Intelligence - Branding Script v1.0 2025"
echo "Developer: Miss Casey Jay Topojani"
echo "GitHub: skyscope-sentinel"
echo -e "${NC}"
echo "Applying Skyscope branding to Debian system..."

# Variables
OS_NAME="Skyscope Sentinel Intelligence Quantum Hybrid Linux Enterprise OS"
LOGO_NAME="plasmoid_orb.png"
LOGO_PATH="/boot/grub/plasmoid_orb.png"
THEME_DIR="/boot/grub/themes/skyscope"
LOG_FILE="/root/skyscope-branding.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_LOGO="$SCRIPT_DIR/$LOGO_NAME"

# Function to log messages
log_message() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | sudo tee -a "$LOG_FILE"
}

# Initialize log file
sudo touch "$LOG_FILE"
sudo chmod 666 "$LOG_FILE"
log_message "Starting Skyscope branding process..."

# Step 1: Verify local logo file
log_message "Checking for $LOGO_NAME in $SCRIPT_DIR..."
if [ ! -f "$LOCAL_LOGO" ]; then
    log_message "ERROR: $LOGO_NAME not found in $SCRIPT_DIR"
    echo "Error: Please ensure $LOGO_NAME is in $SCRIPT_DIR"
    exit 1
fi
if ! file "$LOCAL_LOGO" | grep -q "PNG image data"; then
    log_message "ERROR: $LOCAL_LOGO is not a valid PNG file"
    echo "Error: $LOCAL_LOGO must be a valid PNG file"
    exit 1
fi

# Step 2: Rename OS
log_message "Renaming OS to $OS_NAME..."
sudo sed -i "s/.*PRETTY_NAME.*/PRETTY_NAME=\"$OS_NAME\"/" /etc/os-release
sudo sed -i "s/.*NAME.*/NAME=\"$OS_NAME\"/" /etc/os-release
sudo sed -i "s/.*ID=.*/ID=skyscope/" /etc/os-release
sudo sh -c "echo '$OS_NAME' > /etc/issue"
sudo sh -c "echo '$OS_NAME' > /etc/issue.net"
sudo sh -c "echo 'Welcome to $OS_NAME' > /etc/motd"
sudo hostnamectl set-hostname skyscope-quantum
log_message "OS renamed in /etc/os-release, /etc/issue, /etc/motd, and hostname"

# Step 3: Copy logo for GRUB
log_message "Copying $LOGO_NAME to $LOGO_PATH..."
sudo cp "$LOCAL_LOGO" "$LOGO_PATH"
sudo chmod 644 "$LOGO_PATH"
log_message "Logo copied to $LOGO_PATH"

# Step 4: Configure GRUB theme
log_message "Configuring GRUB bootloader theme..."
sudo mkdir -p "$THEME_DIR"
cat <<EOC | sudo tee "$THEME_DIR/theme.txt"
# Skyscope GRUB Theme
desktop-color: "#000000"
title-text: ""
+ image {
    top = 10%
    left = 40%
    width = 20%
    file = "plasmoid_orb.png"
}
+ label {
    top = 30%
    left = 10%
    width = 80%
    align = "center"
    color = "#00FF00"
    font = "Arial Bold 24"
    text = "$OS_NAME"
}
+ boot_menu {
    left = 30%
    top = 40%
    width = 40%
    height = 40%
    item_font = "Arial Regular 14"
    item_color = "#00FF00"
    selected_item_color = "#FFFFFF"
}
EOC

# Copy logo to theme directory (GRUB looks here for relative paths)
sudo cp "$LOCAL_LOGO" "$THEME_DIR/plasmoid_orb.png"
sudo chmod 644 "$THEME_DIR/plasmoid_orb.png"

# Update /etc/default/grub
cat <<EOC | sudo tee /etc/default/grub
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="$OS_NAME"
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
GRUB_GFXMODE=1920x1080
GRUB_GFXPAYLOAD_LINUX=keep
GRUB_THEME="$THEME_DIR/theme.txt"
EOC

# Update GRUB config
sudo update-grub
log_message "GRUB theme configured with $LOGO_NAME and $OS_NAME"

# Step 5: Replace Debian logos (GDM and desktop)
log_message "Replacing Debian logos..."
# GDM logo (for login screen)
if [ -d "/usr/share/images/desktop-base" ]; then
    sudo cp "$LOCAL_LOGO" /usr/share/images/desktop-base/skyscope-logo.png
    if [ -f "/etc/gdm3/greeter.dconf-defaults" ]; then
        sudo sed -i '/^logo=/d' /etc/gdm3/greeter.dconf-defaults
        echo "logo='/usr/share/images/desktop-base/skyscope-logo.png'" | sudo tee -a /etc/gdm3/greeter.dconf-defaults
        log_message "Updated GDM logo to skyscope-logo.png"
    fi
fi

# Desktop background and icons
if [ -d "/usr/share/backgrounds" ]; then
    sudo cp "$LOCAL_LOGO" /usr/share/backgrounds/skyscope-background.png
    # Update GNOME settings if present
    if command -v gsettings >/dev/null; then
        sudo -u "$SUDO_USER" gsettings set org.gnome.desktop.background picture-uri "file:///usr/share/backgrounds/skyscope-background.png"
        sudo -u "$SUDO_USER" gsettings set org.gnome.desktop.screensaver picture-uri "file:///usr/share/backgrounds/skyscope-background.png"
        log_message "Updated GNOME background to skyscope-background.png"
    fi
fi

# Replace desktop-base logos
if [ -d "/usr/share/desktop-base" ]; then
    sudo find /usr/share/desktop-base -type f -name "*logo*.png" -exec cp "$LOCAL_LOGO" {} \;
    log_message "Replaced desktop-base logos with $LOGO_NAME"
fi

# Step 6: Finalize
log_message "Branding complete. Rebooting in 5 seconds..."
echo "Setup complete! Rebooting to apply changes..."
sleep 5
sudo reboot
