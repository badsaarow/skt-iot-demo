#
# Copyright (c) 2018 HummingLab.io
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.
#

NAME := App_skdemo

$(NAME)_SOURCES := main.c \
		smarthome_conf.c \
		smarthome_pairing.c \
		gmmp.c \
		omp_process.c \
		timeout.c

GLOBAL_DEFINES += USE_MiCOKit_EXT EasyLink_Needs_Reboot
