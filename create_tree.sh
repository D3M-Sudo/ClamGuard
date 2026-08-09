#!/bin/bash
# Alpha — ClamAV Security Suite — Tree Creator Script
# Run from the project root directory

set -e

echo "Creating Alpha project tree..."

mkdir -p .github/workflows
mkdir -p data/icons/hicolor/scalable/apps
mkdir -p data/file-managers/{nemo,nautilus,thunar,dolphin}
mkdir -p data/systemd
mkdir -p debian
mkdir -p po
mkdir -p src/{core,daemon,services,ui/views,ui/widgets}
mkdir -p tests

touch .gitignore

echo "Tree created successfully."
