#!/usr/bin/env bash
set -eu -o pipefail
cd "$(dirname "$(realpath "${0}")")"

DATADIR=${DATADIR:-/usr/share}
LIBDIR=${LIBDIR:-/usr/lib}

install -Dm 0755 ../target/release/ripasso-gnome-search-provider "${LIBDIR}"/ripasso-search-provider/ripasso-gnome-search-provider

install -Dm 0644 conf/org.gnome.Ripasso.search-provider.ini "${DATADIR}"/gnome-shell/search-providers/org.gnome.Ripasso.search-provider.ini

install -Dm 0644 conf/org.gnome.Ripasso.SearchProvider.desktop "${DATADIR}"/applications/org.gnome.Ripasso.SearchProvider.desktop

install -Dm 0644 conf/org.gnome.Ripasso.SearchProvider.service.dbus "${DATADIR}"/dbus-1/services/org.gnome.Ripasso.SearchProvider.service

install -Dm 0644 conf/org.gnome.Ripasso.SearchProvider.service.systemd "${LIBDIR}"/systemd/user/org.gnome.Ripasso.SearchProvider.service
