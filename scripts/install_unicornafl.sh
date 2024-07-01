#!/bin/bash

scriptdir=`dirname "$(realpath -s $0)"`
projdir=`dirname "$scriptdir"`
depsdir="$projdir/tests/dependencies"

sudo apt-get update || exit 1
sudo apt-get install -y `find "$depsdir" -name '*.deb'`|| exit 1
python -m pip install `find "$depsdir" -name '*.whl'` || exit 1
