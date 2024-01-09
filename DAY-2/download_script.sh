#!/bin/bash

# Set the Google Drive file ID
file_id="1xhmqvAmihpcKEj4Z3gpUuohm-Y3lSEU7"

# Set the destination directory
destination_dir="trainingday2"

# Create the destination directory if it doesn't exist
mkdir -p "$destination_dir"
python3 -c "import gdown; gdown.download('https://drive.google.com/uc?id=$1xhmqvAmihpcKEj4Z3gpUuohm-Y3lSEU7', '$destination_dir/IMG_0184')"

echo "Download completed. Files saved in $destination_dir directory."
hostname=$(whoami)
cpuinfo=$(lscpu)
num_cores=$(echo "$cpuinfo" | grep -E '^CPU\(s\):' | awk '{print $2}')
architecture=$(echo "$cpuinfo" | grep 'Architecture' | awk '{print $2}')
total_ram=$(grep -m1 'MemTotal' /proc/meminfo | awk '{print $2}')
available_ram=$(grep -m1 'MemAvailable' /proc/meminfo | awk '{print $2}')
storageinfo=$(df -h)

echo -e "Hostname: $hostname\nNo. of Cores: $num_cores\nArchitecture: $architecture\nTotal RAM:$total_ram kB\nAvailable RAM: $available_ram kB\n$storageinfo" > systeminfo.txtg
