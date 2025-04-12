#!/bin/bash

# Set up terminal colors
GREEN='\033[1;32m'
NC='\033[0m'

# Display header
clear
echo -e "${GREEN}"
echo "Skyscope Sentinel Intelligence - KDE Plasma Customization Script v1.0 2025"
echo "Developer: Miss Casey Jay Topojani"
echo "GitHub: skyscope-sentinel"
echo -e "${NC}"
echo "Customizing KDE Plasma desktop with Sweet theme, Conky, Plank, and floating dock..."

# Variables
OS_NAME="Skyscope Sentinel Intelligence Quantum Hybrid Linux Enterprise OS"
LOG_FILE="/root/skyscope-kde-customize.log"
USER_HOME="/home/$SUDO_USER"
DOWNLOAD_DIR="$USER_HOME/Downloads/Skyscope-Themes"
LATTE_LAYOUT="skyscope.layout.latte"
PLASMA_THEME_URL="https://files.kde.org/store/1253385/Sweet-kde.tar.xz"
CANDY_ICONS_URL="https://files.kde.org/store/1294013/Candy-icons.tar.gz"
TELA_ICONS_URL="https://github.com/vinceliuice/Tela-circle-icon-theme/archive/refs/heads/main.tar.gz"
CONKY_SEAMLESS_URL="https://github.com/BigSainT-Git/conky-seamless/archive/refs/heads/main.tar.gz"
CONKY_CHRONO_URL="https://github.com/BigSainT-Git/conky_chronograph/archive/refs/heads/main.tar.gz"
PLANK_THEMES_URL="https://github.com/heyado/plank-themes/archive/refs/heads/main.tar.gz"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to log messages
log_message() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | sudo tee -a "$LOG_FILE"
}

# Function to handle errors
handle_error() {
    local step="$1"
    local error_msg="$2"
    log_message "ERROR: $step failed - $error_msg"
    echo "Error: $step failed. Check $LOG_FILE for details."
    exit 1
}

# Initialize log file
sudo touch "$LOG_FILE"
sudo chmod 666 "$LOG_FILE"
log_message "Starting KDE Plasma customization process..."

# Step 1: Install dependencies
log_message "Installing dependencies..."
sudo apt update || handle_error "Update apt" "Failed to update package lists"
sudo apt install -y plasma-desktop latte-dock conky plank libkf5config-dev libkf5coreaddons-dev \
    libkf5guiaddons-dev libkf5windowsystem-dev qtbase5-dev git curl unzip fonts-noto \
    fonts-roboto ttf-mscorefonts-installer || handle_error "Install dependencies" "Failed to install packages"

# Step 2: Create download directory
log_message "Creating download directory at $DOWNLOAD_DIR..."
mkdir -p "$DOWNLOAD_DIR" || handle_error "Create download dir" "Failed to create $DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR" || handle_error "Change to download dir" "Failed to access $DOWNLOAD_DIR"

# Step 3: Download and install Sweet Plasma theme
log_message "Installing Sweet Plasma theme..."
if ! [ -f "Sweet-kde.tar.xz" ]; then
    curl -L "$PLASMA_THEME_URL" -o Sweet-kde.tar.xz || handle_error "Download Sweet theme" "Failed to download Sweet-kde.tar.xz"
fi
tar -xf Sweet-kde.tar.xz || handle_error "Extract Sweet theme" "Failed to extract Sweet-kde.tar.xz"
sudo mkdir -p /usr/share/plasma/desktoptheme
sudo cp -r Sweet-kde /usr/share/plasma/desktoptheme/ || handle_error "Install Sweet theme" "Failed to copy Sweet theme"
log_message "Sweet Plasma theme installed"

# Step 4: Download and install Candy icons
log_message "Installing Candy icons..."
if ! [ -f "Candy-icons.tar.gz" ]; then
    curl -L "$CANDY_ICONS_URL" -o Candy-icons.tar.gz || handle_error "Download Candy icons" "Failed to download Candy-icons.tar.gz"
fi
tar -xzf Candy-icons.tar.gz || handle_error "Extract Candy icons" "Failed to extract Candy-icons.tar.gz"
sudo mkdir -p /usr/share/icons
sudo cp -r Candy-icons /usr/share/icons/ || handle_error "Install Candy icons" "Failed to copy Candy icons"
log_message "Candy icons installed"

# Step 5: Download and install Tela Circle icons
log_message "Installing Tela Circle icons..."
if ! [ -f "Tela-circle-icon-theme-main.tar.gz" ]; then
    curl -L "$TELA_ICONS_URL" -o Tela-circle-icon-theme-main.tar.gz || handle_error "Download Tela icons" "Failed to download Tela-circle-icon-theme-main.tar.gz"
fi
tar -xzf Tela-circle-icon-theme-main.tar.gz || handle_error "Extract Tela icons" "Failed to extract Tela-circle-icon-theme-main.tar.gz"
cd Tela-circle-icon-theme-main
sudo ./install.sh -a || handle_error "Install Tela icons" "Failed to install Tela Circle icons"
cd "$DOWNLOAD_DIR"
log_message "Tela Circle icons installed"

# Step 6: Configure Latte Dock
log_message "Configuring Latte Dock..."
# Remove default KDE panel
killall plasmashell
kwriteconfig5 --file ~/.config/plasmashellrc --group PlasmaShell --key panels ""
# Start Latte Dock if not running
latte-dock --replace &>/dev/null &
sleep 2
# Create Skyscope layout
cat <<EOC | tee "$USER_HOME/.config/latte/$LATTE_LAYOUT"
[Containments][1]
formfactor=2
location=4
wallpaperplugin=org.kde.image
[Containments][1][Applets][2]
immutability=1
plugin=org.kde.latte.plasmoid
[Containments][1][Applets][2][Configuration]
PreloadWeight=100
[Containments][1][Applets][2][Configuration][General]
iconSize=48
launchers=applications:firefox.desktop,applications:org.kde.dolphin.desktop,applications:org.kde.konsole.desktop
shadowOpacity=50
shadowSize=70
zoomLevel=10
[Containments][1][ConfigDialog]
DialogHeight=600
DialogWidth=800
[Containments][1][General]
alignment=10
autoDecreaseIconSize=true
backgroundStyle=2
blurRadius=20
editBackground=/usr/share/wallpapers/Next/contents/images/1920x1080.png
maxIconSize=64
panelTransparency=80
plasmaBackground=false
shadows=All
theme=org.kde.latte.default
useThemePanel=true
EOC
# Apply layout
latte-dock --import-layout "$USER_HOME/.config/latte/$LATTE_LAYOUT" || handle_error "Apply Latte layout" "Failed to apply Latte Dock layout"
# Set glassy effect
kwriteconfig5 --file ~/.config/lattedockrc --group Latte --key blurEnabled --type bool true
kwriteconfig5 --file ~/.config/lattedockrc --group Latte --key backgroundOpacity --type int 80
kwriteconfig5 --file ~/.config/lattedockrc --group Latte --key cornerRadius --type int 10
log_message "Latte Dock configured as transparent, glassy, rounded-edged"

# Step 7: Apply Sweet theme and icons via KDE settings
log_message "Applying Sweet theme and Tela Circle icons..."
# Set Plasma theme
lookandfeeltool -a org.kde.breeze.desktop || handle_error "Reset look and feel" "Failed to reset to Breeze"
kwriteconfig5 --file ~/.config/kdeglobals --group KDE --key LookAndFeelPackage --type string "Sweet-kde"
# Set icon theme
kwriteconfig5 --file ~/.config/kdeglobals --group Icons --key Theme --type string "Tela-circle-dark"
# Apply global theme (simulates System Settings)
plasma-apply-desktoptheme Sweet-kde || handle_error "Apply Plasma theme" "Failed to apply Sweet-kde theme"
plasma-apply-icontheme Tela-circle-dark || handle_error "Apply icon theme" "Failed to apply Tela-circle-dark icons"
log_message "Sweet theme and Tela Circle icons applied"

# Step 8: Install and configure Conky
log_message "Installing Conky themes..."
# Download Conky Seamless
if ! [ -f "conky-seamless-main.tar.gz" ]; then
    curl -L "$CONKY_SEAMLESS_URL" -o conky-seamless-main.tar.gz || handle_error "Download Conky Seamless" "Failed to download conky-seamless-main.tar.gz"
fi
tar -xzf conky-seamless-main.tar.gz || handle_error "Extract Conky Seamless" "Failed to extract conky-seamless-main.tar.gz"
mkdir -p "$USER_HOME/.config/conky"
cp -r conky-seamless-main/* "$USER_HOME/.config/conky/" || handle_error "Install Conky Seamless" "Failed to copy Conky Seamless"
# Download Conky Chronograph
if ! [ -f "conky_chronograph-main.tar.gz" ]; then
    curl -L "$CONKY_CHRONO_URL" -o conky_chronograph-main.tar.gz || handle_error "Download Conky Chronograph" "Failed to download conky_chronograph-main.tar.gz"
fi
tar -xzf conky_chronograph-main.tar.gz || handle_error "Extract Conky Chronograph" "Failed to extract conky_chronograph-main.tar.gz"
cp -r conky_chronograph-main/* "$USER_HOME/.config/conky/" || handle_error "Install Conky Chronograph" "Failed to copy Conky Chronograph"
# Create Conky autostart
cat <<EOC | tee "$USER_HOME/.config/autostart/conky.desktop"
[Desktop Entry]
Type=Application
Name=Conky
Exec=conky -c $USER_HOME/.config/conky/conky_seamless.lua &
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOC
cat <<EOC | tee "$USER_HOME/.config/conky/conky.conf"
conky.config = {
    alignment = 'top_right',
    background = true,
    border_width = 1,
    cpu_avg_samples = 2,
    default_color = 'white',
    default_outline_color = 'white',
    default_shade_color = 'black',
    draw_borders = false,
    draw_graph_borders = true,
    draw_outline = false,
    draw_shades = false,
    use_xft = true,
    font = 'DejaVu Sans:size=12',
    gap_x = 5,
    gap_y = 60,
    minimum_height = 5,
    minimum_width = 5,
    net_avg_samples = 2,
    no_buffers = true,
    out_to_console = false,
    out_to_stderr = false,
    extra_newline = false,
    own_window = true,
    own_window_class = 'Conky',
    own_window_type = 'desktop',
    own_window_transparent = true,
    own_window_argb_visual = true,
    own_window_argb_value = 0,
    stippled_borders = 0,
    update_interval = 1.0,
    uppercase = false,
    use_spacer = 'none',
    show_graph_scale = false,
    show_graph_range = false
}
conky.text = [[
\${lua conky_main}
]]
EOC
# Start Conky to test
conky -c "$USER_HOME/.config/conky/conky.conf" &>/dev/null &
log_message "Conky installed with Seamless and Chronograph themes"

# Step 9: Install and configure Plank
log_message "Installing Plank and themes..."
# Download Plank themes
if ! [ -f "plank-themes-main.tar.gz" ]; then
    curl -L "$PLANK_THEMES_URL" -o plank-themes-main.tar.gz || handle_error "Download Plank themes" "Failed to download plank-themes-main.tar.gz"
fi
tar -xzf plank-themes-main.tar.gz || handle_error "Extract Plank themes" "Failed to extract plank-themes-main.tar.gz"
mkdir -p "$USER_HOME/.local/share/plank/themes"
cp -r plank-themes-main/* "$USER_HOME/.local/share/plank/themes/" || handle_error "Install Plank themes" "Failed to copy Plank themes"
# Configure Plank
cat <<EOC | tee "$USER_HOME/.config/plank/dock1/settings"
[dock]
theme=Transparent
position=bottom
offset=0
alignment=center
items-alignment=center
icon-size=48
zoom-enabled=true
zoom-percent=120
hide-mode=auto
unhide-delay=100
hide-delay=300
monitor=""
tooltips-enabled=true
pinned-only=false
lock-items=false
EOC
# Create Plank autostart
cat <<EOC | tee "$USER_HOME/.config/autostart/plank.desktop"
[Desktop Entry]
Type=Application
Name=Plank
Exec=plank
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOC
# Start Plank to test
plank &>/dev/null &
log_message "Plank installed with Transparent theme"

# Step 10: Finalize
log_message "Applying final desktop settings..."
# Refresh Plasma
plasmashell --replace &>/dev/null &
# Clean up
rm -rf "$DOWNLOAD_DIR"
log_message "Customization complete. Desktop refreshed."
echo "Customization complete! Enjoy your Skyscope-themed desktop."
exit 0
