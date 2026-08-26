#!/bin/sh
mkdir config
autoreconf --install -W all -I config -I /usr/share/gettext/m4
