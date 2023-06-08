0. Open a new terminal and execute
	sudo dmesg -wH
	
1. Open a new treminal and execute
	sudo dtoverlay testoverlay.dtbo

   You can use
   	sudo dtoverlay -l
   to check if the devicetree overlay is applied
   
2. Type
	sudo insmod nrf_wifi_spi.ko
   to load the kernel module
