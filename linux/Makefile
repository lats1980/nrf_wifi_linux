ifeq ($(bus), usb)
	MODULE_NAME=nrf_wifi_usb
endif

ifeq ($(bus), spi)
	MODULE_NAME=nrf_wifi_spi
endif

#TODO: only include spi/usb related files
ccflags-y += \
		-DCONFIG_WPA_SUPP \
		-DCONFIG_NRF700X_DATA_TX \
		-D CONFIG_NRF700X_ANT_GAIN_2G=0 \
		-D CONFIG_NRF700X_ANT_GAIN_5G_BAND1=0 \
		-D CONFIG_NRF700X_ANT_GAIN_5G_BAND2=0 \
		-D CONFIG_NRF700X_ANT_GAIN_5G_BAND3=0 \
		-D CONFIG_NRF700X_BAND_2G_LOWER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_2G_UPPER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_1_LOWER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_1_UPPER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_2A_LOWER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_2A_UPPER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_2C_LOWER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_2C_UPPER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_3_LOWER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_3_UPPER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_4_LOWER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_BAND_UNII_4_UPPER_EDGE_BACKOFF=0 \
		-D CONFIG_NRF700X_MAX_TX_TOKENS=12 \
		-D CONFIG_NRF700X_MAX_TX_AGGREGATION=1 \
		-D CONFIG_NRF700X_TX_MAX_DATA_SIZE=1600 \
		-D CONFIG_NRF700X_RX_MAX_DATA_SIZE=1600 \
		-D CONFIG_NRF700X_RX_NUM_BUFS=63 \
		-D CONFIG_NRF700X_MAX_TX_PENDING_QLEN=18 \
		-D CONFIG_NRF700X_REG_DOMAIN=\"00\" \
		-I$(PWD)/inc \
		-I$(PWD)/../osal/os_if/inc \
		-I$(PWD)/../osal/bus_if/bus/qspi/inc \
		-I$(PWD)/../osal/utils/inc \
		-I$(PWD)/../osal/bus_if/bal/inc \
		-I$(PWD)/../osal/fw_if/umac_if/inc \
		-I$(PWD)/../osal/hw_if/hal/inc \
		-I$(PWD)/../osal/hw_if/hal/inc/fw \
		-I$(PWD)/../osal/fw_if/umac_if/inc/fw \
		-I$(PWD)/src/usb/inc

obj-m += $(MODULE_NAME).o

OS_IF_SRC := ../osal/os_if/src
UTILS_SRC := ../osal/utils/src
HW_IF_SRC := ../osal/hw_if/hal/src
BUF_IF_SRC := ../osal/bus_if/bal/src
BUS_IF_QSPI_SRC := ../osal/bus_if/bus/qspi/src
FW_IF_SRC := ../osal/fw_if/umac_if/src

module_objects	+= \
		$(OS_IF_SRC)/osal.o \
		$(UTILS_SRC)/list.o \
		$(UTILS_SRC)/queue.o \
		$(UTILS_SRC)/util.o \
		$(HW_IF_SRC)/hal_api.o \
		$(HW_IF_SRC)/hal_fw_patch_loader.o \
		$(HW_IF_SRC)/hal_interrupt.o \
		$(HW_IF_SRC)/hal_mem.o \
		$(HW_IF_SRC)/hal_reg.o \
		$(HW_IF_SRC)/hpqm.o \
		$(HW_IF_SRC)/pal.o \
		$(BUS_IF_QSPI_SRC)/qspi.o \
		$(BUF_IF_SRC)/bal.o \
		$(FW_IF_SRC)/cmd.o \
		$(FW_IF_SRC)/event.o \
		$(FW_IF_SRC)/fmac_api.o \
		$(FW_IF_SRC)/rx.o \
		$(FW_IF_SRC)/fmac_vif.o \
		$(FW_IF_SRC)/fmac_util.o \
		$(FW_IF_SRC)/fmac_peer.o \
		$(FW_IF_SRC)/tx.o

ifeq ($(bus), usb)
ccflags-y += -DCONFIG_NRF700X_ON_USB_ADAPTER
module_objects += src/nrf_wifi_usb.o
endif

ifeq ($(bus), spi)
ccflags-y += -DCONFIG_NRF700X_ON_QSPI
module_objects += src/nrf_wifi_spi.o
endif

module_objects += \
			src/shim.o \
			src/cfg80211.o

$(MODULE_NAME)-y := $(module_objects) src/main.o

all: clean dt
#	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL) M=$(PWD) modules
	make -C /lib/modules/`uname -r`/build M=`pwd` modules

dt:
	dtc -@ -I dts -O dtb -o testoverlay.dtbo testoverlay.dts

clean:
	rm -rf .*.cmd *.o *.ko
	rm -rf $(OS_IF_SRC)/.*.cmd $(OS_IF_SRC)/*.o
	rm -rf $(UTILS_SRC)/.*.cmd $(UTILS_SRC)/*.o
	rm -rf $(HW_IF_SRC)/.*.cmd $(HW_IF_SRC)/*.o
	rm -rf $(BUF_IF_SRC)/.*.cmd $(BUF_IF_SRC)/*.o
	rm -rf $(BUS_IF_QSPI_SRC)/.*.cmd $(BUS_IF_QSPI_SRC)/*.o
	rm -rf $(FW_IF_SRC)/.*.cmd $(FW_IF_SRC)/*.o
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
