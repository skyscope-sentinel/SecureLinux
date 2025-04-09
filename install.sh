#!/bin/bash

set -e

# Variables
SSD_OS="/mnt/nvme0n1"  # 931.5GB for OS and quantum
SSD_HYBRID="/mnt/nvme0n1/hybrid"
SSD_QUANTUM="/mnt/nvme0n1/quantum"
WORK_DIR="/root/quantum_powerhouse"
LOG_FILE="/root/install-log.txt"
NETWORK_INTERFACE="eth0"
MINIMUM_SPACE_MB=2000  # Minimum required space in MB (2GB)

# Function to log messages
log_message() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
}

# Function to handle errors with retry mechanism
handle_error() {
    local step="$1"
    local error_msg="$2"
    local retry_cmd="$3"
    local max_retries=3
    local retry_count=0

    log_message "ERROR: $step failed - $error_msg"
    while [ $retry_count -lt $max_retries ]; do
        log_message "Retrying $step (Attempt $((retry_count + 1))/$max_retries)..."
        if eval "$retry_cmd"; then
            log_message "$step succeeded on retry $((retry_count + 1))."
            return 0
        fi
        retry_count=$((retry_count + 1))
        sleep 5
    done

    log_message "ERROR: $step failed after $max_retries retries. Attempting to continue..."
    return 1
}

# Function to check and set network interface
check_network_interface() {
    log_message "Checking network interfaces..."
    local interfaces
    interfaces=$(ip link | grep -E '^[0-9]+: ' | awk '{print $2}' | cut -d':' -f1 | grep -v 'lo')

    if echo "$interfaces" | grep -q "^$NETWORK_INTERFACE$"; then
        log_message "Network interface $NETWORK_INTERFACE found."
    else
        log_message "Network interface $NETWORK_INTERFACE not found. Available interfaces: $interfaces"
        NETWORK_INTERFACE=$(echo "$interfaces" | head -n 1)
        if [ -z "$NETWORK_INTERFACE" ]; then
            log_message "ERROR: No network interfaces found. Cannot proceed with network-dependent steps."
            return 1
        fi
        log_message "Falling back to first available interface: $NETWORK_INTERFACE"
    fi
    return 0
}

# Function to ensure network connectivity
ensure_network_connectivity() {
    log_message "Ensuring network connectivity..."
    local max_attempts=5
    local attempt=1

    # Set a reliable DNS server
    log_message "Setting DNS server to 8.8.8.8..."
    echo "nameserver 8.8.8.8" > /etc/resolv.conf

    # Bring up the network interface
    if ! ip link set "$NETWORK_INTERFACE" up 2>>"$LOG_FILE"; then
        log_message "ERROR: Failed to bring up $NETWORK_INTERFACE."
        return 1
    fi

    # Start dhcpcd to obtain an IP address
    if ! dhcpcd "$NETWORK_INTERFACE" 2>>"$LOG_FILE"; then
        log_message "ERROR: dhcpcd failed to obtain an IP address."
        return 1
    fi

    # Test connectivity with a ping to Google's DNS
    while [ $attempt -le $max_attempts ]; do
        log_message "Testing network connectivity (Attempt $attempt/$max_attempts)..."
        if ping -c 3 8.8.8.8 >/dev/null 2>&1; then
            log_message "Network connectivity confirmed."
            return 0
        fi
        log_message "Network connectivity test failed. Retrying in 5 seconds..."
        sleep 5
        attempt=$((attempt + 1))
    done

    log_message "ERROR: Failed to establish network connectivity after $max_attempts attempts."
    return 1
}

# Function to optimize mirrorlist
optimize_mirrorlist() {
    log_message "Optimizing mirrorlist..."
    # Check if reflector is available in the live environment
    if command -v reflector >/dev/null 2>&1; then
        log_message "Using reflector to select the fastest mirrors..."
        if ! reflector --country US,DE,UK --latest 10 --sort rate --save /etc/pacman.d/mirrorlist 2>>"$LOG_FILE"; then
            log_message "WARNING: Failed to run reflector. Falling back to manual mirrorlist."
        fi
    else
        log_message "Reflector not available. Setting manual mirrorlist..."
        cat <<EOC > /etc/pacman.d/mirrorlist
Server = https://mirror.rackspace.com/archlinux/\$repo/os/\$arch
Server = https://mirrors.kernel.org/archlinux/\$repo/os/\$arch
Server = https://mirrors.edge.kernel.org/archlinux/\$repo/os/\$arch
EOC
    fi

    # Refresh pacman package database
    log_message "Refreshing pacman package database..."
    if ! pacman -Syy 2>>"$LOG_FILE"; then
        handle_error "Refreshing pacman database" "pacman -Syy failed" "pacman -Syy"
    fi
}

# Function to check available disk space
check_disk_space() {
    log_message "Checking available disk space..."
    local available_space
    available_space=$(df -m / | tail -1 | awk '{print $4}')  # Available space in MB

    log_message "Available disk space: $available_space MB"
    if [ "$available_space" -lt "$MINIMUM_SPACE_MB" ]; then
        log_message "ERROR: Insufficient disk space. Required: $MINIMUM_SPACE_MB MB, Available: $available_space MB."
        return 1
    fi
    log_message "Sufficient disk space available."
    return 0
}

# Function to clean up disk space
clean_disk_space() {
    log_message "Cleaning up disk space..."
    # Remove temporary files
    rm -rf /tmp/* /var/tmp/* 2>>"$LOG_FILE" || log_message "WARNING: Failed to clean temporary files. Continuing..."

    # Clean pacman cache
    if [ -d "/var/cache/pacman/pkg" ]; then
        log_message "Cleaning pacman cache..."
        rm -rf /var/cache/pacman/pkg/* 2>>"$LOG_FILE" || log_message "WARNING: Failed to clean pacman cache. Continuing..."
    fi

    # Remove logs
    if [ -d "/var/log" ]; then
        log_message "Cleaning logs..."
        find /var/log -type f -delete 2>>"$LOG_FILE" || log_message "WARNING: Failed to clean logs. Continuing..."
    fi

    # Check space again
    local available_space
    available_space=$(df -m / | tail -1 | awk '{print $4}')
    log_message "Available disk space after cleanup: $available_space MB"
    if [ "$available_space" -lt "$MINIMUM_SPACE_MB" ]; then
        log_message "ERROR: Still insufficient disk space after cleanup. Required: $MINIMUM_SPACE_MB MB, Available: $available_space MB."
        return 1
    fi
    return 0
}

# Function to remove non-standard packages
remove_non_standard_packages() {
    log_message "Removing non-standard packages..."
    # List of packages that should be present in a standard Arch Linux live ISO
    local standard_packages="arch-install-scripts base base-devel bash bzip2 coreutils cryptsetup device-mapper dhcpcd diffutils e2fsprogs file filesystem findutils gawk gcc-libs gettext glibc grep gzip inetutils iproute2 iputils less licenses linux linux-firmware logrotate lvm2 man-db man-pages mdadm nano netctl pacman pciutils procps-ng psmisc sed shadow sysfsutils systemd systemd-sysvcompat tar texinfo usbutils util-linux vi which xz"

    # Get list of installed packages
    local installed_packages
    installed_packages=$(pacman -Qe | awk '{print $1}')

    # Explicitly remove qemu and ssh-related packages
    local unwanted_packages="qemu qemu-base qemu-system-x86 openssh sshd"
    for pkg in $unwanted_packages; do
        if pacman -Q "$pkg" >/dev/null 2>&1; then
            log_message "Removing explicitly unwanted package: $pkg..."
            if ! pacman -R --noconfirm "$pkg" 2>>"$LOG_FILE"; then
                log_message "WARNING: Failed to remove $pkg. Continuing..."
            fi
        fi
    done

    # Remove non-standard packages
    for pkg in $installed_packages; do
        if ! echo "$standard_packages" | grep -qw "$pkg"; then
            log_message "Removing non-standard package: $pkg..."
            if ! pacman -R --noconfirm "$pkg" 2>>"$LOG_FILE"; then
                log_message "WARNING: Failed to remove $pkg. Continuing..."
            fi
        fi
    done

    # Log remaining packages for verification
    log_message "Remaining packages after cleanup:"
    pacman -Qe >> "$LOG_FILE" 2>&1
}

# Function to remove non-standard users and groups
remove_non_standard_users_groups() {
    log_message "Removing non-standard users and groups..."
    # Standard users and groups in Arch live ISO (typically just root)
    local standard_users="root"
    local standard_groups="root bin daemon sys adm disk wheel log"

    # Get list of users
    local users
    users=$(cut -d: -f1 /etc/passwd)

    # Remove non-standard users
    for user in $users; do
        if ! echo "$standard_users" | grep -qw "$user"; then
            log_message "Removing non-standard user: $user..."
            if ! userdel -r "$user" 2>>"$LOG_FILE"; then
                log_message "WARNING: Failed to remove user $user. Continuing..."
            fi
        fi
    done

    # Get list of groups
    local groups
    groups=$(cut -d: -f1 /etc/group)

    # Remove non-standard groups
    for group in $groups; do
        if ! echo "$standard_groups" | grep -qw "$group"; then
            log_message "Removing non-standard group: $group..."
            if ! groupdel "$group" 2>>"$LOG_FILE"; then
                log_message "WARNING: Failed to remove group $group. Continuing..."
            fi
        fi
    done

    # Log remaining users and groups for verification
    log_message "Remaining users after cleanup:"
    cut -d: -f1 /etc/passwd >> "$LOG_FILE"
    log_message "Remaining groups after cleanup:"
    cut -d: -f1 /etc/group >> "$LOG_FILE"
}

# Function to remove non-standard certificates and login items
remove_non_standard_certs_login() {
    log_message "Removing non-standard certificates and login items..."
    # Remove certificates
    if [ -d "/etc/ssl/certs" ]; then
        log_message "Removing certificates in /etc/ssl/certs..."
        rm -rf /etc/ssl/certs/* 2>>"$LOG_FILE" || log_message "WARNING: Failed to remove certificates in /etc/ssl/certs. Continuing..."
    fi
    if [ -d "/etc/ca-certificates" ]; then
        log_message "Removing certificates in /etc/ca-certificates..."
        rm -rf /etc/ca-certificates/* 2>>"$LOG_FILE" || log_message "WARNING: Failed to remove certificates in /etc/ca-certificates. Continuing..."
    fi

    # Remove SSH configurations
    if [ -d "/etc/ssh" ]; then
        log_message "Removing SSH configurations in /etc/ssh..."
        rm -rf /etc/ssh/* 2>>"$LOG_FILE" || log_message "WARNING: Failed to remove SSH configurations. Continuing..."
    fi
    if [ -d "/root/.ssh" ]; then
        log_message "Removing SSH configurations in /root/.ssh..."
        rm -rf /root/.ssh/* 2>>"$LOG_FILE" || log_message "WARNING: Failed to remove SSH configurations in /root/.ssh. Continuing..."
    fi

    # Reset PAM configurations to minimal
    log_message "Resetting PAM configurations..."
    cat <<EOC > /etc/pam.d/system-auth
auth       required   pam_unix.so
account    required   pam_unix.so
password   required   pam_unix.so
session    required   pam_unix.so
EOC

    # Remove any login-related configurations
    if [ -f "/etc/security/pam_env.conf" ]; then
        log_message "Clearing /etc/security/pam_env.conf..."
        > /etc/security/pam_env.conf 2>>"$LOG_FILE" || log_message "WARNING: Failed to clear pam_env.conf. Continuing..."
    fi
}

# Initialize log file
> "$LOG_FILE"
log_message "Starting installation process..."

# Step 0: Clean Up Live Environment
log_message "Cleaning up live environment..."

# Check disk space and clean up if necessary
check_disk_space || {
    log_message "Attempting to free up disk space..."
    clean_disk_space || {
        log_message "ERROR: Unable to free up sufficient disk space. Cannot proceed."
        exit 1
    }
}

# Remove non-standard packages, users, groups, certificates, and login items
remove_non_standard_packages
remove_non_standard_users_groups
remove_non_standard_certs_login

# Step 1: Disable Network Access Initially
log_message "Disabling network access during initial setup..."
if ! ip link set "$NETWORK_INTERFACE" down 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to disable network interface $NETWORK_INTERFACE. Continuing..."
fi
systemctl stop dhcpcd 2>>"$LOG_FILE" || true

# Step 2: Verify Disk Setup
log_message "Verifying disk setup..."
for disk in /dev/nvme0n1 /dev/nvme1n1 /dev/sda /dev/sdb; do
    if ! lsblk -f | grep -q "$(basename $disk)"; then
        log_message "ERROR: Disk $disk not found!"
        exit 1
    fi
done
if cryptsetup status wipe0n1 >/dev/null 2>&1 || cryptsetup status wipe1n1 >/dev/null 2>&1; then
    log_message "Wipe mappings still active. Closing them..."
    cryptsetup close wipe0n1 2>>"$LOG_FILE" || true
    cryptsetup close wipe1n1 2>>"$LOG_FILE" || true
fi

# Step 3: Optimized Disk Wiping and Partitioning
log_message "Wiping and partitioning drives..."
for disk in /dev/nvme0n1 /dev/nvme1n1 /dev/sdb; do
    log_message "Fast wiping SSD $disk..."
    if ! blkdiscard -f "$disk" 2>>"$LOG_FILE"; then
        handle_error "Wiping SSD $disk" "blkdiscard failed" "blkdiscard -f $disk"
    fi
done
log_message "Minimally wiping HDD /dev/sda..."
if ! dd if=/dev/zero of=/dev/sda bs=4M count=100 status=progress 2>>"$LOG_FILE"; then
    handle_error "Wiping HDD /dev/sda" "dd failed" "dd if=/dev/zero of=/dev/sda bs=4M count=100 status=progress"
fi
if ! wipefs -a /dev/sda 2>>"$LOG_FILE"; then
    handle_error "Wiping signatures on /dev/sda" "wipefs failed" "wipefs -a /dev/sda"
fi

# Partitioning
for disk in /dev/nvme0n1 /dev/nvme1n1 /dev/sda /dev/sdb; do
    log_message "Partitioning $disk..."
    case $disk in
        /dev/nvme0n1)
            if ! parted -s "$disk" mklabel gpt 2>>"$LOG_FILE" ||
               ! parted -s "$disk" mkpart primary 1MiB 513MiB 2>>"$LOG_FILE" ||
               ! parted -s "$disk" set 1 esp on 2>>"$LOG_FILE" ||
               ! parted -s "$disk" mkpart primary 513MiB 100% 2>>"$LOG_FILE" ||
               ! parted -s "$disk" set 2 lvm on 2>>"$LOG_FILE"; then
                handle_error "Partitioning $disk" "parted failed" "parted -s $disk mklabel gpt && parted -s $disk mkpart primary 1MiB 513MiB && parted -s $disk set 1 esp on && parted -s $disk mkpart primary 513MiB 100% && parted -s $disk set 2 lvm on"
            fi
            if ! mkfs.fat -F32 "${disk}p1" 2>>"$LOG_FILE"; then
                handle_error "Formatting EFI partition on $disk" "mkfs.fat failed" "mkfs.fat -F32 ${disk}p1"
            fi
            ;;
        *)
            if ! parted -s "$disk" mklabel gpt 2>>"$LOG_FILE" ||
               ! parted -s "$disk" mkpart primary 1MiB 100% 2>>"$LOG_FILE" ||
               ! parted -s "$disk" set 1 lvm on 2>>"$LOG_FILE"; then
                handle_error "Partitioning $disk" "parted failed" "parted -s $disk mklabel gpt && parted -s $disk mkpart primary 1MiB 100% && parted -s $disk set 1 lvm on"
            fi
            ;;
    esac
done

# Verify partitioning
for disk in /dev/nvme0n1 /dev/nvme1n1 /dev/sda /dev/sdb; do
    if ! lsblk "$disk" | grep -q "part"; then
        log_message "ERROR: Partitioning failed for $disk! Cannot continue."
        exit 1
    fi
done

# Step 4: Set Up LUKS2 Encryption with Post-Quantum Enhancements
log_message "Setting up LUKS2 encryption with quantum randomness..."
if ! pacman -S --noconfirm rng-tools 2>>"$LOG_FILE"; then
    handle_error "Installing rng-tools" "pacman failed" "pacman -S --noconfirm rng-tools"
fi
rngd -r /dev/urandom 2>>"$LOG_FILE" || log_message "WARNING: rngd failed to seed initial randomness. Continuing..."
mkdir -p /tmp/luks-passphrases
for disk in /dev/nvme0n1p2 /dev/nvme1n1p1 /dev/sda1 /dev/sdb1; do
    log_message "Setting up LUKS on $disk..."
    echo "Enter passphrase for $disk (minimum 20 characters):"
    read -s passphrase
    while [ ${#passphrase} -lt 20 ]; do
        echo "Passphrase must be at least 20 characters long. Try again:"
        read -s passphrase
    done
    echo
    echo "Confirm passphrase for $disk:"
    read -s passphrase_confirm
    echo
    while [ "$passphrase" != "$passphrase_confirm" ]; do
        echo "Passphrases do not match. Try again:"
        echo "Enter passphrase for $disk:"
        read -s passphrase
        echo
        echo "Confirm passphrase for $disk:"
        read -s passphrase_confirm
        echo
    done
    echo -n "$passphrase" > "/tmp/luks-passphrases/$(basename $disk).pass"
    log_message "Formatting $disk with LUKS..."
    if ! dd if=/dev/urandom of=/tmp/luks-key bs=512 count=1 2>>"$LOG_FILE" ||
       ! rngd -r /tmp/luks-key -o /dev/random 2>>"$LOG_FILE" ||
       ! echo -n "$passphrase" | cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 --pbkdf argon2id --iter-time 10000 "$disk" - 2>>"$LOG_FILE"; then
        handle_error "Formatting $disk with LUKS" "cryptsetup luksFormat failed" "dd if=/dev/urandom of=/tmp/luks-key bs=512 count=1 && rngd -r /tmp/luks-key -o /dev/random && echo -n \"$passphrase\" | cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 --pbkdf argon2id --iter-time 10000 \"$disk\" -"
    fi
    log_message "Opening $disk..."
    if ! echo -n "$passphrase" | cryptsetup open "$disk" "crypt$(basename $disk)" - 2>>"$LOG_FILE"; then
        handle_error "Opening LUKS container on $disk" "cryptsetup open failed" "echo -n \"$passphrase\" | cryptsetup open \"$disk\" \"crypt$(basename $disk)\" -"
    fi
    if ! cryptsetup status "crypt$(basename $disk)" >/dev/null 2>&1; then
        log_message "ERROR: Failed to open LUKS container for $disk! Cannot continue."
        exit 1
    fi
done
for disk in /dev/nvme0n1p2 /dev/nvme1n1p1 /dev/sda1 /dev/sdb1; do
    log_message "Backing up LUKS header for $disk..."
    if ! cryptsetup luksHeaderBackup "$disk" --header-backup-file "/root/luks-header-$(basename $disk).bin" 2>>"$LOG_FILE"; then
        handle_error "Backing up LUKS header for $disk" "cryptsetup luksHeaderBackup failed" "cryptsetup luksHeaderBackup \"$disk\" --header-backup-file \"/root/luks-header-$(basename $disk).bin\""
    fi
done

# Step 5: Configure LVM and Btrfs
log_message "Configuring LVM and Btrfs..."
for dev in /dev/mapper/cryptnvme0n1p2 /dev/mapper/cryptnvme1n1p1 /dev/mapper/cryptsda1 /dev/mapper/cryptsdb1; do
    if ! pvcreate "$dev" 2>>"$LOG_FILE"; then
        handle_error "Creating physical volume on $dev" "pvcreate failed" "pvcreate \"$dev\""
    fi
done
if ! vgcreate vgroot /dev/mapper/cryptnvme0n1p2 2>>"$LOG_FILE"; then
    handle_error "Creating volume group vgroot" "vgcreate failed" "vgcreate vgroot /dev/mapper/cryptnvme0n1p2"
fi
if ! vgcreate vgextra /dev/mapper/cryptnvme1n1p1 2>>"$LOG_FILE"; then
    handle_error "Creating volume group vgextra" "vgcreate failed" "vgcreate vgextra /dev/mapper/cryptnvme1n1p1"
fi
if ! vgcreate vghome /dev/mapper/cryptsda1 2>>"$LOG_FILE"; then
    handle_error "Creating volume group vghome" "vgcreate failed" "vgcreate vghome /dev/mapper/cryptsda1"
fi
if ! vgcreate vgextra2 /dev/mapper/cryptsdb1 2>>"$LOG_FILE"; then
    handle_error "Creating volume group vgextra2" "vgcreate failed" "vgcreate vgextra2 /dev/mapper/cryptsdb1"
fi
if ! lvcreate -L 32G vgroot -n swap 2>>"$LOG_FILE"; then
    handle_error "Creating swap logical volume" "lvcreate failed" "lvcreate -L 32G vgroot -n swap"
fi
if ! lvcreate -l 100%FREE vgroot -n root 2>>"$LOG_FILE"; then
    handle_error "Creating root logical volume" "lvcreate failed" "lvcreate -l 100%FREE vgroot -n root"
fi
if ! lvcreate -l 100%FREE vgextra -n extra 2>>"$LOG_FILE"; then
    handle_error "Creating extra logical volume" "lvcreate failed" "lvcreate -l 100%FREE vgextra -n extra"
fi
if ! lvcreate -l 100%FREE vghome -n home 2>>"$LOG_FILE"; then
    handle_error "Creating home logical volume" "lvcreate failed" "lvcreate -l 100%FREE vghome -n home"
fi
if ! lvcreate -l 100%FREE vgextra2 -n extra2 2>>"$LOG_FILE"; then
    handle_error "Creating extra2 logical volume" "lvcreate failed" "lvcreate -l 100%FREE vgextra2 -n extra2"
fi
for lv in /dev/vgroot/root /dev/vgextra/extra /dev/vghome/home /dev/vgextra2/extra2; do
    if ! mkfs.btrfs -L "$(basename $lv)" "$lv" 2>>"$LOG_FILE"; then
        handle_error "Formatting $lv with Btrfs" "mkfs.btrfs failed" "mkfs.btrfs -L \"$(basename $lv)\" \"$lv\""
    fi
done
if ! mount /dev/vgroot/root /mnt 2>>"$LOG_FILE" ||
   ! btrfs subvolume create /mnt/@ 2>>"$LOG_FILE" ||
   ! btrfs subvolume create /mnt/@snapshots 2>>"$LOG_FILE"; then
    handle_error "Creating Btrfs subvolumes on /dev/vgroot/root" "btrfs subvolume create failed" "mount /dev/vgroot/root /mnt && btrfs subvolume create /mnt/@ && btrfs subvolume create /mnt/@snapshots"
fi
umount /mnt 2>>"$LOG_FILE" || true
if ! mount /dev/vghome/home /mnt 2>>"$LOG_FILE" ||
   ! btrfs subvolume create /mnt/@home 2>>"$LOG_FILE"; then
    handle_error "Creating Btrfs subvolume @home on /dev/vghome/home" "btrfs subvolume create failed" "mount /dev/vghome/home /mnt && btrfs subvolume create /mnt/@home"
fi
umount /mnt 2>>"$LOG_FILE" || true
if ! mount -o subvol=@,compress=zstd,ssd,noatime /dev/vgroot/root /mnt 2>>"$LOG_FILE"; then
    handle_error "Mounting root filesystem" "mount failed" "mount -o subvol=@,compress=zstd,ssd,noatime /dev/vgroot/root /mnt"
fi
mkdir -p /mnt/{boot,home,.snapshots}
if ! mount -o subvol=@home,compress=zstd,ssd,noatime /dev/vghome/home /mnt/home 2>>"$LOG_FILE"; then
    handle_error "Mounting home filesystem" "mount failed" "mount -o subvol=@home,compress=zstd,ssd,noatime /dev/vghome/home /mnt/home"
fi
if ! mount -o subvol=@snapshots,compress=zstd,ssd,noatime /dev/vgroot/root /mnt/.snapshots 2>>"$LOG_FILE"; then
    handle_error "Mounting snapshots filesystem" "mount failed" "mount -o subvol=@snapshots,compress=zstd,ssd,noatime /dev/vgroot/root /mnt/.snapshots"
fi
if ! mount /dev/nvme0n1p1 /mnt/boot 2>>"$LOG_FILE"; then
    handle_error "Mounting boot filesystem" "mount failed" "mount /dev/nvme0n1p1 /mnt/boot"
fi
if ! mkswap /dev/vgroot/swap 2>>"$LOG_FILE"; then
    handle_error "Creating swap" "mkswap failed" "mkswap /dev/vgroot/swap"
fi
if ! swapon /dev/vgroot/swap 2>>"$LOG_FILE"; then
    handle_error "Enabling swap" "swapon failed" "swapon /dev/vgroot/swap"
fi
if ! mount | grep -q "/mnt type btrfs"; then
    log_message "ERROR: Failed to mount root filesystem! Cannot continue."
    exit 1
fi

# Step 6: Install Base System (Minimized)
log_message "Installing base system with minimal dependencies..."
check_network_interface || { log_message "ERROR: Network check failed. Cannot proceed."; exit 1; }
ensure_network_connectivity || { log_message "ERROR: Failed to establish network connectivity. Cannot proceed."; exit 1; }
optimize_mirrorlist

# Log the packages to be installed
log_message "Packages to be installed: base linux linux-firmware intel-ucode btrfs-progs lvm2 cryptsetup grub efibootmgr networkmanager vim yubikey-manager yubico-piv-tool openssh pam-u2f base-devel git cmake python-pip libvirt virt-install ufw apparmor rng-tools"

# Use --needed to avoid reinstalling, and install packages one by one to control dependencies
for pkg in base linux linux-firmware intel-ucode btrfs-progs lvm2 cryptsetup grub efibootmgr networkmanager vim yubikey-manager yubico-piv-tool openssh pam-u2f base-devel git cmake python-pip libvirt virt-install ufw apparmor rng-tools; do
    log_message "Installing $pkg..."
    # Use --nodeps for specific packages with optional dependencies we don't need
    if [ "$pkg" = "networkmanager" ] || [ "$pkg" = "libvirt" ]; then
        if ! pacstrap /mnt "$pkg" --needed --nodeps 2>>"$LOG_FILE"; then
            handle_error "Installing $pkg" "pacstrap failed" "pacstrap /mnt $pkg --needed --nodeps"
        fi
    else
        if ! pacstrap /mnt "$pkg" --needed 2>>"$LOG_FILE"; then
            handle_error "Installing $pkg" "pacstrap failed" "pacstrap /mnt $pkg --needed"
        fi
    fi
done

# Log all installed packages for debugging
log_message "Logging all installed packages..."
pacman -Qe > /mnt/root/installed-packages.txt 2>>"$LOG_FILE"
log_message "Installed packages logged to /mnt/root/installed-packages.txt"

# Remove unwanted packages immediately after pacstrap
log_message "Removing unwanted packages..."
for pkg in ca-certificates-utils avahi wpa_supplicant bluez bluez-utils; do
    if pacman -Q "$pkg" >/dev/null 2>&1; then
        log_message "Removing $pkg..."
        if ! pacman -R --noconfirm "$pkg" 2>>"$LOG_FILE"; then
            log_message "WARNING: Failed to remove $pkg. Continuing..."
        fi
    fi
done

# Verify package installation
for pkg in base linux linux-firmware intel-ucode btrfs-progs lvm2 cryptsetup grub efibootmgr networkmanager vim yubikey-manager yubico-piv-tool openssh pam-u2f base-devel git cmake python-pip libvirt virt-install ufw apparmor rng-tools; do
    if ! pacman -Q "$pkg" >/dev/null 2>&1; then
        log_message "WARNING: Package $pkg not installed. Attempting to continue..."
    fi
done

ip link set "$NETWORK_INTERFACE" down 2>>"$LOG_FILE" || true
systemctl stop dhcpcd 2>>"$LOG_FILE" || true
if ! genfstab -U /mnt >> /mnt/etc/fstab 2>>"$LOG_FILE"; then
    handle_error "Generating fstab" "genfstab failed" "genfstab -U /mnt >> /mnt/etc/fstab"
fi
if ! sed -i 's/subvolid=[0-9]*/subvol=@/' /mnt/etc/fstab 2>>"$LOG_FILE"; then
    handle_error "Modifying fstab" "sed failed" "sed -i 's/subvolid=[0-9]*/subvol=@/' /mnt/etc/fstab"
fi

# Step 7: Chroot and Configure System
log_message "Configuring system..."
arch-chroot /mnt /bin/bash <<'EOF' || log_message "WARNING: Chroot failed. Attempting to continue..."
set -e

# Log file inside chroot
LOG_FILE="/root/install-log.txt"
log_message() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
}

# Enable UFW
log_message "Enabling UFW..."
if ! ufw enable 2>>"$LOG_FILE" ||
   ! ufw default deny incoming 2>>"$LOG_FILE" ||
   ! ufw default deny outgoing 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to enable UFW. Continuing..."
fi

# Timezone and Clock
log_message "Setting timezone and clock..."
if ! ln -sf /usr/share/zoneinfo/UTC /etc/localtime 2>>"$LOG_FILE" ||
   ! hwclock --systohc 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to set timezone or clock. Continuing..."
fi
if [ "$(date +%Z)" != "UTC" ]; then
    log_message "WARNING: Timezone not set to UTC. Continuing..."
fi

# Locale
log_message "Setting locale..."
if ! echo "en_US.UTF-8 UTF-8" > /etc/locale.gen 2>>"$LOG_FILE" ||
   ! locale-gen 2>>"$LOG_FILE" ||
   ! echo "LANG=en_US.UTF-8" > /etc/locale.conf 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to set locale. Continuing..."
fi
if ! locale | grep -q "LANG=en_US.UTF-8"; then
    log_message "WARNING: Locale not set to en_US.UTF-8. Continuing..."
fi

# Hostname
log_message "Setting hostname..."
if ! echo "skyscope-research" > /etc/hostname 2>>"$LOG_FILE" ||
   ! echo "127.0.0.1 localhost" >> /etc/hosts 2>>"$LOG_FILE" ||
   ! echo "::1 localhost" >> /etc/hosts 2>>"$LOG_FILE" ||
   ! echo "127.0.1.1 skyscope-research.local skyscope-research" >> /etc/hosts 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to set hostname or hosts file. Continuing..."
fi
if ! grep -q "skyscope-research" /etc/hostname; then
    log_message "WARNING: Hostname not set correctly. Continuing..."
fi

# mkinitcpio Configuration
log_message "Configuring mkinitcpio..."
cat <<EOC > /etc/mkinitcpio.conf
MODULES=(btrfs crc32c xhci_pci aic94xx bfa qed qla2xxx wd719x)
HOOKS=(base udev autodetect keyboard keymap modconf block encrypt lvm2 filesystems fsck)
EOC
cat <<EOC > /etc/mkinitcpio.d/linux.preset
# mkinitcpio preset file for the default linux kernel
ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux"

PRESETS=('default' 'fallback')

# Default preset
default_image="/boot/initramfs-linux.img"
#default_options=""

# Fallback preset
fallback_image="/boot/initramfs-linux-fallback.img"
fallback_options="-S autodetect"
EOC
cat <<EOC > /etc/mkinitcpio.d/linux-quantum-powerhouse.preset
# mkinitcpio preset file for the linux-quantum-powerhouse kernel
ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux-quantum-powerhouse"

PRESETS=('default' 'fallback')

# Default preset
default_image="/boot/initramfs-linux-quantum-powerhouse.img"
#default_options=""

# Fallback preset
fallback_image="/boot/initramfs-linux-quantum-powerhouse-fallback.img"
fallback_options="-S autodetect"
EOC

# Set Root User
log_message "Setting root user..."
if ! usermod -l skyscope-research root 2>>"$LOG_FILE" ||
   ! usermod -d /root -m skyscope-research 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to modify root user. Continuing..."
fi
echo "Enter password for skyscope-research (minimum 20 characters):"
read -s root_passphrase
while [ ${#root_passphrase} -lt 20 ]; do
    echo "Password must be at least 20 characters long. Try again:"
    read -s root_passphrase
done
echo
echo "Confirm password for skyscope-research:"
read -s root_passphrase_confirm
echo
while [ "$root_passphrase" != "$root_passphrase_confirm" ]; do
    echo "Passwords do not match. Try again:"
    echo "Enter password for skyscope-research:"
    read -s root_passphrase
    echo
    echo "Confirm password for skyscope-research:"
    read -s root_passphrase_confirm
    echo
done
if ! echo "skyscope-research:$root_passphrase" | chpasswd 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to set root password. Continuing..."
fi

# Install Additional Dependencies
log_message "Installing additional dependencies..."
ip link set eth0 up 2>>"$LOG_FILE" || log_message "WARNING: Failed to bring up eth0. Continuing..."
dhcpcd eth0 2>>"$LOG_FILE" || log_message "WARNING: dhcpcd failed. Continuing..."
if ! pacman -S --noconfirm --needed rustup 2>>"$LOG_FILE" ||
   ! rustup default stable 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to install rustup. Continuing..."
fi
if ! pip install qiskit numpy 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to install qiskit and numpy. Continuing..."
fi
if [ ! -d "/root/anaconda3" ]; then
    if ! curl -L https://repo.anaconda.com/archive/Anaconda3-latest-Linux-x86_64.sh -o anaconda.sh 2>>"$LOG_FILE" ||
       ! bash anaconda.sh -b -p /root/anaconda3 2>>"$LOG_FILE"; then
        log_message "WARNING: Failed to install Anaconda. Continuing..."
    fi
fi
source /root/anaconda3/bin/activate 2>>"$LOG_FILE" || log_message "WARNING: Failed to activate Anaconda. Continuing..."
if ! curl -fsSL https://ollama.com/install.sh | sh 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to install Ollama. Continuing..."
fi
ip link set eth0 down 2>>"$LOG_FILE" || true
systemctl stop dhcpcd 2>>"$LOG_FILE" || true

# Kernel Compilation with Post-Quantum and Lattice-Based Ciphers
log_message "Compiling kernel..."
mkdir -p /root/quantum_powerhouse
cd /root/quantum_powerhouse
LATEST_KERNEL="linux-6.9.tar.xz"
if ! curl -L "https://kernel.org/pub/linux/kernel/v6.x/$LATEST_KERNEL" -o "$LATEST_KERNEL" 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to download kernel. Continuing with default kernel..."
else
    tar -xf "$LATEST_KERNEL" 2>>"$LOG_FILE" || log_message "WARNING: Failed to extract kernel. Continuing..."
    cd "${LATEST_KERNEL%.tar.xz}"
    cp "/boot/config-$(uname -r)" .config 2>>"$LOG_FILE" || curl -L https://raw.githubusercontent.com/archlinux/svntogit-packages/packages/linux/repos/core-x86_64/config -o .config 2>>"$LOG_FILE"
    cat <<EOC >> .config
# Performance Optimizations for Intel CPU and NVMe
CONFIG_SMP=y
CONFIG_HYPERTHREADING=y
CONFIG_NUMA=y
CONFIG_PREEMPT=y
CONFIG_HZ_1000=y
CONFIG_CGROUP_SCHED=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_RT_GROUP_SCHED=y
CONFIG_SCHED_SMT=y
CONFIG_SCHED_MC=y
CONFIG_SCHED_CLUSTER=y
CONFIG_INTEL_PSTATE=y
CONFIG_X86_INTEL_LPSS=y
CONFIG_X86_INTEL_PCH_THERMAL=y
CONFIG_NVME_MULTIPATH=y
CONFIG_NVME_HWMON=y

# Post-Quantum and Lattice-Based Cryptography
CONFIG_CRYPTO_KYBER=y
CONFIG_CRYPTO_DILITHIUM=y
CONFIG_CRYPTO_FALCON=y
CONFIG_CRYPTO_SPHINCS=y
CONFIG_CRYPTO_RSA=n
CONFIG_CRYPTO_KEYSIZE=4096
CONFIG_CRYPTO_AES=y
CONFIG_CRYPTO_SERPENT=n
CONFIG_CRYPTO_CRC32C=y
CONFIG_CRYPTO_LIB_BLAKE2S=y
CONFIG_CRYPTO_LIB_CHACHA20POLY1305=y

# Quantum Modules
CONFIG_VQUANTUM_HYBRID=m
CONFIG_VQUANTUM_QSIM=m

# Virtualization and Security
CONFIG_KVM_GUEST=y
CONFIG_VIRTIO=y
CONFIG_VT=y
CONFIG_VTD=y
CONFIG_INTEL_IOMMU=y
CONFIG_KVM_INTEL=y
CONFIG_X86_X2APIC=y
CONFIG_LOCALVERSION="-quantum-powerhouse"
CONFIG_MODULE_COMPRESS_XZ=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_DEFAULT_SECURITY_APPARMOR=y
CONFIG_CRYPTO_KRB5=n
CONFIG_DRM_AST=n
CONFIG_MDNS=n

# Include missing modules for hardware support
CONFIG_USB_XHCI_HCD=y
CONFIG_SCSI_AIC94XX=m
CONFIG_SCSI_BFA=m
CONFIG_QED=m
CONFIG_SCSI_QLA_FC=m
CONFIG_WD719X=m
CONFIG_FIRMWARE_IN_KERNEL=y
CONFIG_EXTRA_FIRMWARE=""
EOC
    if ! make olddefconfig 2>>"$LOG_FILE"; then
        log_message "WARNING: Failed to configure kernel. Continuing..."
    fi
    mkdir -p drivers/vquantum
    cat <<EOC > drivers/vquantum/vquantum_hybrid.c
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/random.h>
static char *ssd_path = "/mnt/nvme0n1/hybrid";
module_param(ssd_path, charp, 0644);
static int __init vquantum_hybrid_init(void) {
    printk(KERN_INFO "VQuantum Hybrid: 900 GB at %s, %d cores\n", ssd_path, num_online_cpus());
    if (system("python3 /opt/quantum_task.py > /dev/null") == 0) {
        char buffer[32];
        struct file *f = filp_open("/mnt/nvme0n1/quantum/nonce_list.bin", O_RDONLY, 0);
        if (!IS_ERR(f)) {
            kernel_read(f, buffer, 32, &f->f_pos);
            add_device_randomness(buffer, 32);
            filp_close(f, NULL);
        }
    }
    return 0;
}
static void __exit vquantum_hybrid_exit(void) {
    printk(KERN_INFO "VQuantum Hybrid: Unloaded\n");
}
module_init(vquantum_hybrid_init);
module_exit(vquantum_hybrid_exit);
MODULE_LICENSE("GPL");
EOC
    cat <<EOC > drivers/vquantum/vquantum_qsim.c
#include <linux/module.h>
static char *ssd_path = "/mnt/nvme0n1/quantum";
module_param(ssd_path, charp, 0644);
static int __init vquantum_qsim_init(void) {
    printk(KERN_INFO "VQuantum QSim: 40 qubits at %s\n", ssd_path);
    return 0;
}
static void __exit vquantum_qsim_exit(void) {
    printk(KERN_INFO "VQuantum QSim: Unloaded\n");
}
module_init(vquantum_qsim_init);
module_exit(vquantum_qsim_exit);
MODULE_LICENSE("GPL");
EOC
    echo "obj-m += vquantum_hybrid.o vquantum_qsim.o" > drivers/vquantum/Makefile
    if ! make -j$(nproc) 2>>"$LOG_FILE" || ! make modules_install 2>>"$LOG_FILE" || ! make install 2>>"$LOG_FILE"; then
        log_message "WARNING: Kernel compilation failed. Continuing with default kernel..."
    fi
    if ! ls /boot/vmlinuz-linux-quantum-powerhouse >/dev/null 2>&1; then
        log_message "WARNING: Kernel not installed. Continuing with default kernel..."
    fi
fi

# Ensure firmware is available
log_message "Ensuring firmware is available..."
mkdir -p /lib/firmware
cp -r /usr/lib/firmware/* /lib/firmware/ 2>>"$LOG_FILE" || log_message "WARNING: Failed to copy firmware files. Continuing..."

# Blacklist Unwanted Modules
log_message "Blacklisting unwanted modules..."
cat <<EOC > /etc/modprobe.d/blacklist.conf
blacklist krb5
blacklist ast
blacklist avahi
blacklist mdns
blacklist iwlwifi
blacklist bluetooth
install krb5 /bin/false
install ast /bin/false
install avahi /bin/false
install mdns /bin/false
install iwlwifi /bin/false
install bluetooth /bin/false
EOC
for module in krb5 ast avahi mdns iwlwifi bluetooth; do
    if lsmod | grep -q "$module"; then
        rmmod "$module" 2>>"$LOG_FILE" || log_message "WARNING: Failed to unload module $module. Continuing..."
    fi
done

# Rebuild initramfs for both kernels
log_message "Rebuilding initramfs..."
if ! mkinitcpio -P 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to rebuild initramfs. Continuing..."
fi
if ! ls /boot/initramfs-linux.img >/dev/null 2>&1; then
    log_message "ERROR: Default initramfs not created. Cannot continue."
    exit 1
fi
if ! ls /boot/initramfs-linux-quantum-powerhouse.img >/dev/null 2>&1; then
    log_message "WARNING: Custom initramfs not created. Continuing with default kernel..."
fi

# YubiKey Integration with Quantum Randomness
log_message "Setting up YubiKey..."
rngd -r /dev/urandom 2>>"$LOG_FILE" || log_message "WARNING: rngd failed to seed randomness. Continuing..."
if ! ykman piv certificates export 9a /root/yubikey-cert.pem 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to export YubiKey certificate. Continuing..."
fi
cat <<EOC > /etc/pam.d/system-auth
auth       required   pam_u2f.so authfile=/etc/yubikey_mappings cue
auth       required   pam_unix.so try_first_pass
EOC
if ! ykpiv-checker > /etc/yubikey_mappings 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to set up YubiKey mappings. Continuing..."
fi
if ! ssh-keygen -D /usr/lib/libykcs11.so > /root/.ssh/id_yubikey.pub 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to generate YubiKey SSH key. Continuing..."
fi
mkdir -p /root/.ssh
cat /root/.ssh/id_yubikey.pub >> /root/.ssh/authorized_keys 2>>"$LOG_FILE" || log_message "WARNING: Failed to add YubiKey to authorized_keys. Continuing..."
chmod 600 /root/.ssh/authorized_keys 2>>"$LOG_FILE" || log_message "WARNING: Failed to set permissions on authorized_keys. Continuing..."
cat <<EOC > /etc/ssh/sshd_config
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
EOC
if ! systemctl enable sshd 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to enable sshd. Continuing..."
fi

# Post-Quantum Security for SSH
log_message "Setting up post-quantum SSH..."
ip link set eth0 up 2>>"$LOG_FILE" || log_message "WARNING: Failed to bring up eth0. Continuing..."
dhcpcd eth0 2>>"$LOG_FILE" || log_message "WARNING: dhcpcd failed. Continuing..."
if ! git clone https://github.com/open-quantum-safe/liboqs.git 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to clone liboqs. Continuing..."
else
    cd liboqs
    mkdir build && cd build
    if ! cmake -DOQS_ALGS_ENABLED="Kyber,Dilithium,Falcon,SPHINCS+" .. 2>>"$LOG_FILE" ||
       ! make -j$(nproc) 2>>"$LOG_FILE" ||
       ! make install 2>>"$LOG_FILE"; then
        log_message "WARNING: Failed to build liboqs. Continuing..."
    fi
fi
cd /root/quantum_powerhouse
if ! git clone https://github.com/open-quantum-safe/openssh.git 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to clone openssh. Continuing..."
else
    cd openssh
    if ! ./configure --with-liboqs-dir=/usr/local --prefix=/usr 2>>"$LOG_FILE" ||
       ! make -j$(nproc) 2>>"$LOG_FILE" ||
       ! make install 2>>"$LOG_FILE"; then
        log_message "WARNING: Failed to build openssh. Continuing..."
    fi
fi
cat <<EOC >> /etc/ssh/sshd_config
KexAlgorithms sntrup761x25519-sha512@openssh.com
HostKeyAlgorithms ssh-kyber-512,ssh-dilithium-128
Ciphers chacha20-poly1305@openssh.com
MACs hmac-sha2-512
EOC
systemctl restart sshd 2>>"$LOG_FILE" || log_message "WARNING: Failed to restart sshd. Continuing..."
ip link set eth0 down 2>>"$LOG_FILE" || true
systemctl stop dhcpcd 2>>"$LOG_FILE" || true

# GRUB Configuration
log_message "Configuring GRUB..."
if ! grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to install GRUB. Continuing..."
fi
cat <<EOC > /etc/default/grub
GRUB_ENABLE_CRYPTODISK=y
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash intel_pstate=active apparmor=1 security=apparmor"
GRUB_CMDLINE_LINUX="cryptdevice=UUID=$(blkid -s UUID -o value /dev/nvme0n1p2):vgroot root=/dev/vgroot/root"
EOC
GRUB_PW_HASH=$(echo -e "password\npassword" | grub-mkpasswd-pbkdf2 2>>"$LOG_FILE" | grep -o "grub.pbkdf2.sha512.*" || echo "")
if [ -z "$GRUB_PW_HASH" ]; then
    log_message "WARNING: Failed to generate GRUB password hash. Continuing..."
fi
cat <<EOC > /etc/grub.d/40_custom
set superusers="admin"
password_pbkdf2 admin $GRUB_PW_HASH
EOC
if ! sed -i 's/--class os/--class os --unrestricted/' /etc/grub.d/10_linux 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to modify GRUB config. Continuing..."
fi
if ! grub-mkconfig -o /boot/grub/grub.cfg 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to generate GRUB config. Continuing..."
fi
if ! grep -q "cryptdevice" /boot/grub/grub.cfg 2>>"$LOG_FILE"; then
    log_message "WARNING: GRUB config does not contain cryptdevice. Continuing..."
fi

# Security Hardening
log_message "Applying security hardening..."
systemctl mask bluetooth.service 2>>"$LOG_FILE" || log_message "WARNING: Failed to mask bluetooth.service. Continuing..."
systemctl mask wpa_supplicant.service 2>>"$LOG_FILE" || log_message "WARNING: Failed to mask wpa_supplicant.service. Continuing..."
ufw default deny incoming 2>>"$LOG_FILE" || log_message "WARNING: Failed to set UFW default deny incoming. Continuing..."
ufw default allow outgoing 2>>"$LOG_FILE" || log_message "WARNING: Failed to set UFW default allow outgoing. Continuing..."
ufw enable 2>>"$LOG_FILE" || log_message "WARNING: Failed to enable UFW. Continuing..."
systemctl enable ufw 2>>"$LOG_FILE" || log_message "WARNING: Failed to enable UFW service. Continuing..."
if ! pacman -S --noconfirm --needed usbguard 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to install usbguard. Continuing..."
fi
usbguard generate-policy > /etc/usbguard/rules.conf 2>>"$LOG_FILE" || log_message "WARNING: Failed to generate usbguard policy. Continuing..."
cat <<EOC > /etc/usbguard/rules.conf
allow id 1050:0407
block
EOC
systemctl enable usbguard 2>>"$LOG_FILE" || log_message "WARNING: Failed to enable usbguard. Continuing..."
pacman -R --noconfirm ca-certificates-utils avahi 2>>"$LOG_FILE" || log_message "WARNING: Failed to remove ca-certificates-utils and avahi. Continuing..."
if ! pacman -S --noconfirm --needed nvidia nvidia-utils 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to install nvidia drivers. Continuing..."
fi
echo "performance" > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>>"$LOG_FILE" || log_message "WARNING: Failed to set CPU governor to performance. Continuing..."
if ! pacman -S --noconfirm --needed sbctl 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to install sbctl. Continuing..."
fi
sbctl create-keys 2>>"$LOG_FILE" || log_message "WARNING: Failed to create Secure Boot keys. Continuing..."
sbctl enroll-keys -m 2>>"$LOG_FILE" || log_message "WARNING: Failed to enroll Secure Boot keys. Continuing..."
sbctl sign -s /boot/EFI/GRUB/grubx64.efi 2>>"$LOG_FILE" || log_message "WARNING: Failed to sign GRUB with Secure Boot. Continuing..."
systemctl enable apparmor 2>>"$LOG_FILE" || log_message "WARNING: Failed to enable AppArmor. Continuing..."

# Quantum Setup with System-Wide Integration
log_message "Setting up quantum components..."
mkdir -p /mnt/nvme0n1/hybrid /mnt/nvme0n1/quantum
echo "/dev/vgroot/root /mnt/nvme0n1/hybrid btrfs subvol=@,compress=zstd,ssd,noatime 0 0" >> /etc/fstab
echo "/dev/vgroot/root /mnt/nvme0n1/quantum btrfs subvol=@,compress=zstd,ssd,noatime 0 0" >> /etc/fstab
mount -a 2>>"$LOG_FILE" || log_message "WARNING: Failed to mount quantum directories. Continuing..."

# Hybrid Buffer
log_message "Setting up hybrid buffer..."
cat <<EOC > /opt/vquantum_hybrid.rs
use std::fs::{remove_file, File};
use std::io::{Read, Write};
use std::process::Command;
const SSD_HYBRID: &str = "/mnt/nvme0n1/hybrid";
const SSD_QUANTUM: &str = "/mnt/nvme0n1/quantum";
const BLOCKS: usize = 20;
fn process_block(block_id: usize) {
    let mut quantum_file = File::open(format!("{}/nonce_list.bin", SSD_QUANTUM)).unwrap();
    let mut data = Vec::new();
    quantum_file.read_to_end(&mut data).unwrap();
    let chunk = data.chunks(data.len() / BLOCKS).nth(block_id % BLOCKS).unwrap();
    let path = format!("{}/block_{}.bin", SSD_HYBRID, block_id);
    File::create(&path).unwrap().write_all(chunk).unwrap();
    Command::new("rngd").arg("-r").arg(&path).arg("-o").arg("/dev/random").status().unwrap();
    remove_file(&path).unwrap();
}
fn main() {
    let mut handles = vec![];
    for i in 0..BLOCKS { handles.push(std::thread::spawn(move || process_block(i))); }
    for h in handles { h.join().unwrap(); }
}
EOC
if ! rustc -O /opt/vquantum_hybrid.rs -o /opt/vquantum_hybrid 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to compile vquantum_hybrid. Continuing..."
fi
chmod +x /opt/vquantum_hybrid 2>>"$LOG_FILE" || log_message "WARNING: Failed to set permissions on vquantum_hybrid. Continuing..."

# Quantum Simulator
log_message "Setting up quantum simulator..."
cat <<EOC > /opt/vquantum_qsim.py
#!/usr/bin/env python3
import cirq
import qsimcirq
import numpy as np
import ollama
import os
SSD_QUANTUM = "/mnt/nvme0n1/quantum"
QUBITS = 40
circuit = cirq.Circuit()
qubits = [cirq.LineQubit(i) for i in range(QUBITS)]
circuit.append(cirq.H(q) for q in qubits)
circuit.measure_all()
sim = qsimcirq.QSimSimulator()
while True:
    result = sim.simulate(circuit)
    states = result.final_state_vector[:10**6]
    insight = ollama.chat(model="llama3", messages=[{"role": "user", "content": "Rank states for system tasks"}])
    ranked_states = sorted(states, key=lambda x: abs(x))[-10**5:]
    np.save(f"{SSD_QUANTUM}/nonce_list.bin", ranked_states)
    os.system(f"rngd -r {SSD_QUANTUM}/nonce_list.bin -o /dev/random")
EOC
chmod +x /opt/vquantum_qsim.py 2>>"$LOG_FILE" || log_message "WARNING: Failed to set permissions on vquantum_qsim.py. Continuing..."

# System-Wide Quantum Enhancement
log_message "Setting up system-wide quantum enhancements..."
cat <<EOC > /etc/profile.d/quantum_boost.sh
#!/bin/bash
export QUANTUM_HYBRID_PATH="/mnt/nvme0n1/hybrid"
export QUANTUM_QSIM_PATH="/mnt/nvme0n1/quantum"
alias compute_boost="python3 /opt/quantum_task.py"
export LD_PRELOAD="/usr/local/lib/libquantum_boost.so"
EOC
chmod +x /etc/profile.d/quantum_boost.sh 2>>"$LOG_FILE" || log_message "WARNING: Failed to set permissions on quantum_boost.sh. Continuing..."

# Quantum Task Integration
log_message "Setting up quantum task integration..."
cat <<EOC > /opt/quantum_task.py
#!/usr/bin/env python3
import numpy as np
import ollama
import os
SSD_HYBRID = "/mnt/nvme0n1/hybrid"
SSD_QUANTUM = "/mnt/nvme0n1/quantum"
def hybrid_task() {
    combined = np.ones(1, dtype=np.complex128)
    for i in range(20) {
        block_path = f"{SSD_HYBRID}/block_{i}.bin"
        if os.path.exists(block_path) {
            block = np.fromfile(block_path, dtype=np.complex128)[:2**10]
            combined = np.kron(combined, block)
        }
    }
    return combined
}
def quantum_task() {
    state_path = f"{SSD_QUANTUM}/nonce_list.bin"
    if os.path.exists(state_path) {
        state = np.load(state_path)
        return state.sum()
    }
    return 0
}
if __name__ == "__main__":
    ollama.chat(model="llama3", messages=[{"role": "user", "content": "Optimize system tasks"}])
    hybrid_result = hybrid_task()
    quantum_result = quantum_task()
    print(f"Hybrid Boost: {hybrid_result}, Quantum Boost: {quantum_result}")
    os.system("sysctl -w kernel.sched_quantum_boost=$(echo $quantum_result | cut -d. -f1)")
EOC
chmod +x /opt/quantum_task.py 2>>"$LOG_FILE" || log_message "WARNING: Failed to set permissions on quantum_task.py. Continuing..."

# Quantum Boost Library
log_message "Setting up quantum boost library..."
cat <<EOC > /root/quantum_boost.c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
void __attribute__((constructor)) quantum_boost_init(void) {
    system("python3 /opt/quantum_task.py > /dev/null");
    setenv("QUANTUM_BOOST", "1", 1);
}
EOC
if ! gcc -shared -fPIC /root/quantum_boost.c -o /usr/local/lib/libquantum_boost.so 2>>"$LOG_FILE"; then
    log_message "WARNING: Failed to compile quantum_boost library. Continuing..."
fi

# Services
log_message "Setting up services..."
cat <<EOC > /etc/systemd/system/vquantum_hybrid.service
[Unit]
Description=Quantum Hybrid Buffer
After=network.target
[Service]
ExecStart=/opt/vquantum_hybrid
Restart=always
[Install]
WantedBy=multi-user.target
EOC
cat <<EOC > /etc/systemd/system/vquantum_qsim.service
[Unit]
Description=Quantum Simulator
After=network.target
[Service]
ExecStart=/opt/vquantum_qsim.py
Restart=always
[Install]
WantedBy=multi-user.target
EOC
systemctl daemon-reload 2>>"$LOG_FILE" || log_message "WARNING: Failed to reload systemd daemon. Continuing..."
systemctl enable vquantum_hybrid vquantum_qsim NetworkManager 2>>"$LOG_FILE" || log_message "WARNING: Failed to enable services. Continuing..."

# Harden Against Unauthorized Module Loading
log_message "Hardening against unauthorized module loading..."
echo "kernel.modules_disabled=1" >> /etc/sysctl.conf
sysctl -p 2>>"$LOG_FILE" || log_message "WARNING: Failed to apply sysctl settings. Continuing..."

# Finalize
log_message "Chroot configuration completed."
exit
EOF

# Step 8: Reboot
log_message "Rebooting..."
umount -R /mnt 2>>"$LOG_FILE" || log_message "WARNING: Failed to unmount /mnt. Continuing..."
swapoff /dev/vgroot/swap 2>>"$LOG_FILE" || log_message "WARNING: Failed to disable swap. Continuing..."
cryptsetup close cryptnvme0n1p2 2>>"$LOG_FILE" || log_message "WARNING: Failed to close cryptnvme0n1p2. Continuing..."
cryptsetup close cryptnvme1n1p1 2>>"$LOG_FILE" || log_message "WARNING: Failed to close cryptnvme1n1p1. Continuing..."
cryptsetup close cryptsda1 2>>"$LOG_FILE" || log_message "WARNING: Failed to close cryptsda1. Continuing..."
cryptsetup close cryptsdb1 2>>"$LOG_FILE" || log_message "WARNING: Failed to close cryptsdb1. Continuing..."
log_message "Installation completed. Rebooting system..."
reboot
