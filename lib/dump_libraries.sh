#!/bin/bash

OUTDIR=$1
if [ -z ${OUTDIR} ]; then
    echo "Need to specify output root dir for libraries"
    exit 1
fi

set -e

LIBDIR=`pwd`

for LIB in *.a; do
    LIB=${LIB%.a}
    echo $LIB
    mkdir -p ${OUTDIR}/${LIB}
    cd ${OUTDIR}/$LIB
    ar x ${LIBDIR}/${LIB}.a
    for O in *.o; do
	O=${O%.o}
	xtobjdis ${O}.o > ${O}.S
	rm ${O}.o
    done
done


