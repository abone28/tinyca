#!/bin/bash

mkdir -p locale/de/LC_MESSAGES

msgfmt po/de.po -o locale/de/LC_MESSAGES/tinyca.mo
