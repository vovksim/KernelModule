iDESCRIPTION = "Firewall Logger Kernel Module"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/files/common-licenses/GPL-2.0-only;md5=801f80980d171dd6425610833a22dbe6"

SRC_URI = "file://firewall_logger.c \
           file://Makefile"

S = "${WORKDIR}"

inherit module

KERNEL_MODULE_AUTOLOAD += "firewall_logger"

FILES:${PN} += "/lib/modules/${KERNEL_VERSION}/extra/firewall_logger.ko"

