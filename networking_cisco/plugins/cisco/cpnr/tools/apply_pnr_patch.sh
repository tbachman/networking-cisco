#!/bin/sh

echo "Applying PNR patch in the testing env"

FILE_DST="$1/src/neutron/neutron/plugins/cisco"
FILE_SRC="$2/*"

echo "Checking Directory Existance: $FILE_DST"

if [ ! -d "$FILE_DST" ]; then
  echo "Directory $FILE_DST does not exist, aborting..."
  exit 1
fi

cd $FILE_DST
mkdir -p cpnr

# Copy py files to plugins directory
cp -r $FILE_SRC $FILE_DST/cpnr

