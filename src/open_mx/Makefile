# $Id: Makefile $
#
# @Copyright@
#

PKGROOT		= /opt/open-mx/source
REDHAT.ROOT     = $(CURDIR)/../../

RPM.EXTRAS 	= %define __os_install_post /usr/lib/rpm/brp-compress

-include $(ROCKSROOT)/etc/Rules.mk
include Rules.mk

build:

rpm::
	echo " Don't use open-mx"

install::
	echo " Don't use open-mx"
	#mkdir -p $(ROOT)/$(PKGROOT)
	#install -m 644 $(NAME)-$(VERSION).tar.gz $(ROOT)/$(PKGROOT)/
	#mkdir -p $(ROOT)/etc//ld.so.conf.d
	#install -m 644 open-mx.conf $(ROOT)/etc//ld.so.conf.d
clean::
	rm -rf $(NAME)-$(VERSION)
