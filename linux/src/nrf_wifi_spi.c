#include <linux/module.h>
#include <linux/init.h>
#include <linux/spi/spi.h>
#include <linux_fmac_main.h>

#include <osal_structs.h>
#include <hal_structs.h>
#include <qspi.h>
#include "shim.h"


int nrf_wifi_init(void);
int nrf_wifi_exit(void);


extern struct wifi_nrf_drv_priv_lnx rpu_drv_priv_lnx;



static struct of_device_id nrf7002_driver_ids[] = {
	{
		.compatible = "nordic,nrf7002",
	}, { /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, nrf7002_driver_ids);

static struct spi_device_id nrf7002[] = {
	{"nrf7002", 0},
	{ },
};
MODULE_DEVICE_TABLE(spi, nrf7002);

/**
 * @brief This function is called on loading the driver 
 */
static int nrf7002_probe(struct spi_device *spi)
{
    nrf_wifi_init();	
	
	struct wifi_nrf_rpu_priv_lnx* rpu_priv = NULL;
	int i;

	struct wifi_nrf_bus_qspi_priv* qspi_priv;
	struct lnx_shim_bus_qspi_priv *linux_qspi_priv = NULL;


	qspi_priv = (struct wifi_nrf_bus_qspi_priv *)rpu_drv_priv_lnx.fmac_priv->hpriv->bpriv->bus_priv;
	linux_qspi_priv = (struct lnx_shim_bus_qspi_priv *)qspi_priv->os_qspi_priv;
	linux_qspi_priv->spi_dev = spi;
	linux_qspi_priv->irq_enabled = false;

	rpu_priv = wifi_nrf_fmac_dev_add_lnx(&spi->dev);
    if (!rpu_priv) {
        printk("%s: failed\n", __func__);
        goto err;
    }
	dev_set_drvdata(&spi->dev, rpu_priv);
	return 0;
err:
	return -1;
}

/**
 * @brief This function is called on unloading the driver 
 */
static int nrf7002_remove(struct spi_device *spi)
{
	struct wifi_nrf_rpu_priv_lnx* rpu_priv = NULL;

	printk("nRF WiFi driver disconnect\n");
	rpu_priv = dev_get_drvdata(&spi->dev);
	if (!rpu_priv) {
		printk("Fail to get rpu priv data\n");
	}
	wifi_nrf_fmac_dev_rem_lnx(rpu_priv);
	
	nrf_wifi_exit();

	struct wifi_nrf_bus_qspi_priv* qspi_priv;
	struct lnx_shim_bus_qspi_priv *linux_qspi_priv = NULL;


	qspi_priv = (struct wifi_nrf_bus_qspi_priv *)rpu_drv_priv_lnx.fmac_priv->hpriv->bpriv->bus_priv;
	linux_qspi_priv = (struct lnx_shim_bus_qspi_priv *)qspi_priv->os_qspi_priv;

	if(linux_qspi_priv->irq_enabled) {
		free_irq(gpiod_to_irq(linux_qspi_priv->host_irq), linux_qspi_priv);
	}
    return 0;
}

static struct spi_driver my_driver = {
	.probe = nrf7002_probe,
	.remove = nrf7002_remove,
	.id_table = nrf7002,
	.driver = {
		.name = "nrf7002",
		.of_match_table = nrf7002_driver_ids,
	},
};

static int __init nrf_wifi_module_init(void)
{

	int result;

	result = spi_register_driver(&my_driver);
	if (!result) {
		printk(KERN_ERR "loading nRF7002 driver ok\n");
	}
	else {
		printk(KERN_ERR "loading nRF7002 driver failed\n");
	}
	return result;
}

static void __exit nrf_wifi_module_exit(void)
{
	spi_unregister_driver(&my_driver);
	
	struct wifi_nrf_bus_qspi_priv* qspi_priv;
	struct lnx_shim_bus_qspi_priv *linux_qspi_priv = NULL;


	qspi_priv = (struct wifi_nrf_bus_qspi_priv *)rpu_drv_priv_lnx.fmac_priv->hpriv->bpriv->bus_priv;
	linux_qspi_priv = (struct lnx_shim_bus_qspi_priv *)qspi_priv->os_qspi_priv;

	if(linux_qspi_priv->irq_enabled) {
		free_irq(gpiod_to_irq(linux_qspi_priv->host_irq), linux_qspi_priv);
	}
}


module_init(nrf_wifi_module_init);
module_exit(nrf_wifi_module_exit);

/* Meta Information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("INTERNAL");
MODULE_DESCRIPTION("A driver for nRF7002");