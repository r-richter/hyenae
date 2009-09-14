#!/bin/bash

HYENAE_VERSION="0.34-2"
BUILD_ARCHITECTURE="i386"

BUILD_DIR_PATH="./hyenae_"$HYENAE_VERSION"_"$BUILD_ARCHITECTURE

# Create build directory
mkdir -p $BUILD_DIR_PATH"/DEBIAN"
mkdir -p $BUILD_DIR_PATH"/etc/hyenae"
mkdir -p $BUILD_DIR_PATH"/etc/init.d"
mkdir -p $BUILD_DIR_PATH"/usr/local/bin"
mkdir -p $BUILD_DIR_PATH"/usr/local/share/man/man1"
mkdir -p $BUILD_DIR_PATH"/usr/local/share/doc/hyenae"

# Remove special permissions from build directory
chmod -R a-s $BUILD_DIR_PATH

# Calculate installation size
INSTALLED_SIZE=$[ \
  `stat -c %s ./../../../src/hyenae` + \
  `stat -c %s ./../../../src/hyenaed` + \
  `stat -c %s ./../../../man/hyenae.1` + \
  `stat -c %s ./../../../man/hyenaed.1` + \
  `stat -c %s ./../../../HOWTO` + \
  `stat -c %s ./../../../LICENSE` + \
  `stat -c %s ./../../../README` + \
  `stat -c %s ./extra/hyenaed` + \
  `stat -c %s ./extra/hyenaed.args`]

# Copy files to build folder
cp "./extra/hyenaed.args" $BUILD_DIR_PATH"/etc/hyenae/"
cp "./extra/hyenaed" $BUILD_DIR_PATH"/etc/init.d/"
cp "./../../../src/hyenae" $BUILD_DIR_PATH"/usr/local/bin/"
cp "./../../../src/hyenaed" $BUILD_DIR_PATH"/usr/local/bin/"
cp "./../../../man/hyenae.1" $BUILD_DIR_PATH"/usr/local/share/man/man1/"
cp "./../../../man/hyenaed.1" $BUILD_DIR_PATH"/usr/local/share/man/man1/"
cp "./../../../HOWTO" $BUILD_DIR_PATH"/usr/local/share/doc/hyenae"
cp "./../../../LICENSE" $BUILD_DIR_PATH"/usr/local/share/doc/hyenae"
cp "./../../../README" $BUILD_DIR_PATH"/usr/local/share/doc/hyenae"

# Write control file
echo "Package: hyenae" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Version: "$HYENAE_VERSION >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Section: network" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Priority: optional" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Architecture: "$BUILD_ARCHITECTURE >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Essential: no" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Depends: libpcap0.8 (>= 0.9.8-5), libdumbnet1 (>= 1.8-1.5)" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Installed-Size: "$INSTALLED_SIZE >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Maintainer: Robin Richter [richterr@users.sourceforge.net]" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Provides: hyenae" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "Description: Hyenae is a highly flexible and platform independent network packet" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        generator. It allows you to reproduce low level ethernet attack scenarios (such" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        as MITM, DoS and DDoS) to reveal the potential security vulnerabilities of your" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        network." >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        ." >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        The following document is a brief overview of the Hyenae utility suite and its" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        command line usage. The following paragraphs outline how Hyenae can be used" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        to reproduce low level ethernet attack scenarios (such as MITM, DoS and DDoS) to" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        reveal potential security vulnerabilities of your network. Some examples are" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        enumerated here to illustrate the potential of the Hyenae utility suite. These" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        concise examples are aimed at users such as network administrators or analysts," >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        and assume advanced technical knowledge. For a complete overview of all possible" >> $BUILD_DIR_PATH"/DEBIAN/control"
echo "        command line arguments, please refer to the README file or the Manpages." >> $BUILD_DIR_PATH"/DEBIAN/control"

# Build .deb
dpkg -b $BUILD_DIR_PATH "./hyenae_"$HYENAE_VERSION"_"$BUILD_ARCHITECTURE".deb"

# Remove build folder
rm -rf $BUILD_DIR_PATH
