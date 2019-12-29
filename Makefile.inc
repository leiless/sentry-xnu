#
# Put user-defined variables here
#

include SentryDSN.inc

KEXTNAME=sentry-xnu
KEXTVERSION=0000.00.01
KEXTBUILD:=$(shell ./bump_build.sh)
BUNDLEDOMAIN=net.trineo

