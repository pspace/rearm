#!/bin/sh

for d in */; do cp Makefile.template "$d"Makefile; done
