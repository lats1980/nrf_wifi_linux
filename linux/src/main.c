
#include <linux/module.h>
#include <rpu_fw_patches.h>
#include <fmac_api.h>
#include <linux_fmac_main.h>

#if defined(CONFIG_NRF700X_ON_USB_ADAPTER)
#include "nrf_wifi_usb.h"
#endif


/* 3 bytes for addreess, 3 bytes for length */
#define MAX_PKT_RAM_TX_ALIGN_OVERHEAD 6

#ifndef CONFIG_NRF700X_RADIO_TEST
struct wifi_nrf_drv_priv_lnx rpu_drv_priv_lnx;

#ifdef CONFIG_NRF700X_DATA_TX

#define MAX_RX_QUEUES 3

#define MAX_TX_FRAME_SIZE \
	(CONFIG_NRF700X_TX_MAX_DATA_SIZE + TX_BUF_HEADROOM)
#define TOTAL_TX_SIZE \
	(CONFIG_NRF700X_MAX_TX_TOKENS * CONFIG_NRF700X_TX_MAX_DATA_SIZE)
#define TOTAL_RX_SIZE \
	(CONFIG_NRF700X_RX_NUM_BUFS * CONFIG_NRF700X_RX_MAX_DATA_SIZE)

static const unsigned char aggregation = 1;
static const unsigned char wmm = 1;
static const unsigned char max_num_tx_agg_sessions = 4;
static const unsigned char max_num_rx_agg_sessions = 8;
static const unsigned char reorder_buf_size = 16;
static const unsigned char max_rxampdu_size = MAX_RX_AMPDU_SIZE_64KB;

static const unsigned char max_tx_aggregation = CONFIG_NRF700X_MAX_TX_AGGREGATION;

static const unsigned int rx1_num_bufs = CONFIG_NRF700X_RX_NUM_BUFS / MAX_RX_QUEUES;
static const unsigned int rx2_num_bufs = CONFIG_NRF700X_RX_NUM_BUFS / MAX_RX_QUEUES;
static const unsigned int rx3_num_bufs = CONFIG_NRF700X_RX_NUM_BUFS / MAX_RX_QUEUES;

static const unsigned int rx1_buf_sz = CONFIG_NRF700X_RX_MAX_DATA_SIZE;
static const unsigned int rx2_buf_sz = CONFIG_NRF700X_RX_MAX_DATA_SIZE;
static const unsigned int rx3_buf_sz = CONFIG_NRF700X_RX_MAX_DATA_SIZE;

static const unsigned char rate_protection_type;
#else
/* Reduce buffers to Scan only operation */
static const unsigned int rx1_num_bufs = 2;
static const unsigned int rx2_num_bufs = 2;
static const unsigned int rx3_num_bufs = 2;

static const unsigned int rx1_buf_sz = 1000;
static const unsigned int rx2_buf_sz = 1000;
static const unsigned int rx3_buf_sz = 1000;
#endif

struct wifi_nrf_drv_priv_lnx rpu_drv_priv_lnx;

/* TODO add missing code */
#endif /* !CONFIG_NRF700X_RADIO_TEST */

struct wifi_nrf_rpu_priv_lnx *wifi_nrf_fmac_dev_add_lnx(struct device *dev)
{
	enum wifi_nrf_status status = WIFI_NRF_STATUS_FAIL;
	struct wifi_nrf_rpu_priv_lnx *rpu_priv = NULL;
	struct wifi_nrf_fmac_fw_info fw_info;
	void *rpu_ctx = NULL;
#if defined(CONFIG_BOARD_NRF7001)
	enum op_band op_band = BAND_24G;
#else /* CONFIG_BOARD_NRF7001 */
	enum op_band op_band = BAND_ALL;
#endif /* CONFIG_BOARD_NRF7001 */
	struct nrf_wifi_umac_add_vif_info add_vif_info;
	struct nrf_wifi_umac_chg_vif_state_info chg_vif_info;
	struct nrf_vif_priv *vif_ctx;
	int i;

#ifdef CONFIG_NRF_WIFI_LOW_POWER
	int sleep_type = -1;
	sleep_type = HW_SLEEP_ENABLE;
#endif /* CONFIG_NRF_WIFI_LOW_POWER */
	struct nrf_wifi_tx_pwr_ctrl_params tx_pwr_ctrl_params;

	//rpu_priv = &rpu_drv_priv_lnx.rpu_priv;
	rpu_priv = nrf_cfg80211_init(dev);
	if (!rpu_priv) {
		goto out;
	}
	rpu_priv->drv_priv = &rpu_drv_priv_lnx;
	rpu_ctx = wifi_nrf_fmac_dev_add(rpu_drv_priv_lnx.fmac_priv, rpu_priv);
	if (!rpu_ctx) {
		printk("%s: wifi_nrf_fmac_dev_add failed\n", __func__);
		rpu_priv = NULL;
		goto out;
	}

	rpu_priv->rpu_ctx = rpu_ctx;

	/* Load the FW patches to the RPU */
	memset(&fw_info, 0, sizeof(fw_info));
	fw_info.lmac_patch_pri.data = wifi_nrf_lmac_patch_pri_bimg;
	fw_info.lmac_patch_pri.size = sizeof(wifi_nrf_lmac_patch_pri_bimg);
	fw_info.lmac_patch_sec.data = wifi_nrf_lmac_patch_sec_bin;
	fw_info.lmac_patch_sec.size = sizeof(wifi_nrf_lmac_patch_sec_bin);
	fw_info.umac_patch_pri.data = wifi_nrf_umac_patch_pri_bimg;
	fw_info.umac_patch_pri.size = sizeof(wifi_nrf_umac_patch_pri_bimg);
	fw_info.umac_patch_sec.data = wifi_nrf_umac_patch_sec_bin;
	fw_info.umac_patch_sec.size = sizeof(wifi_nrf_umac_patch_sec_bin);
	status = wifi_nrf_fmac_fw_load(rpu_ctx, &fw_info);
	if (status != WIFI_NRF_STATUS_SUCCESS) {
		printk("%s: wifi_nrf_fmac_fw_load failed\n", __func__);
		goto out;
	}

	tx_pwr_ctrl_params.ant_gain_2g = CONFIG_NRF700X_ANT_GAIN_2G;
	tx_pwr_ctrl_params.ant_gain_5g_band1 = CONFIG_NRF700X_ANT_GAIN_5G_BAND1;
	tx_pwr_ctrl_params.ant_gain_5g_band2 = CONFIG_NRF700X_ANT_GAIN_5G_BAND2;
	tx_pwr_ctrl_params.ant_gain_5g_band3 = CONFIG_NRF700X_ANT_GAIN_5G_BAND3;
	tx_pwr_ctrl_params.band_edge_2g_lo = CONFIG_NRF700X_BAND_2G_LOWER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_2g_hi = CONFIG_NRF700X_BAND_2G_UPPER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_1_lo = CONFIG_NRF700X_BAND_UNII_1_LOWER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_1_hi = CONFIG_NRF700X_BAND_UNII_1_UPPER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_2a_lo = CONFIG_NRF700X_BAND_UNII_2A_LOWER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_2a_hi = CONFIG_NRF700X_BAND_UNII_2A_UPPER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_2c_lo = CONFIG_NRF700X_BAND_UNII_2C_LOWER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_2c_hi = CONFIG_NRF700X_BAND_UNII_2C_UPPER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_3_lo = CONFIG_NRF700X_BAND_UNII_3_LOWER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_3_hi = CONFIG_NRF700X_BAND_UNII_3_UPPER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_4_lo = CONFIG_NRF700X_BAND_UNII_4_LOWER_EDGE_BACKOFF;
	tx_pwr_ctrl_params.band_edge_5g_unii_4_hi = CONFIG_NRF700X_BAND_UNII_4_UPPER_EDGE_BACKOFF;


	status = wifi_nrf_fmac_dev_init(rpu_ctx,
					NULL,
#ifdef CONFIG_NRF_WIFI_LOW_POWER
					sleep_type,
#endif /* CONFIG_NRF_WIFI_LOW_POWER */
					NRF_WIFI_DEF_PHY_CALIB,
					op_band,
					&tx_pwr_ctrl_params);
	if (status != WIFI_NRF_STATUS_SUCCESS) {
		printk("%s: wifi_nrf_fmac_dev_init failed\n", __func__);
		goto out;
	}

	for (i = 0; i < MAX_NUM_VIFS; i++) {
		rpu_priv->vif_priv[i].rpu_priv = rpu_priv;
		rpu_priv->vif_priv[i].wiphy = rpu_priv->wiphy;
	}
	vif_ctx = &rpu_priv->vif_priv[0];
	memset(&add_vif_info, 0, sizeof(add_vif_info));
	add_vif_info.iftype = NRF_WIFI_IFTYPE_STATION;
	memcpy(add_vif_info.ifacename, "wlan0", strlen("wlan0"));
	vif_ctx->vif_idx = wifi_nrf_fmac_add_vif(rpu_ctx,
							vif_ctx,
							&add_vif_info);
	if (vif_ctx->vif_idx >= MAX_NUM_VIFS) {
		printk("%s: FMAC returned invalid interface index\n", __func__);
		goto out;
	}

	status = wifi_nrf_fmac_otp_mac_addr_get(rpu_ctx,
						vif_ctx->vif_idx,
						vif_ctx->mac_addr);
	if (status != WIFI_NRF_STATUS_SUCCESS) {
		printk("%s: Fetching of MAC address from OTP failed\n",
			__func__);
		goto out;
	}

	status = wifi_nrf_fmac_set_vif_macaddr(rpu_ctx, vif_ctx->vif_idx, vif_ctx->mac_addr);
	if (status != WIFI_NRF_STATUS_SUCCESS) {
		printk("%s: MAC address change failed\n",
			__func__);
		goto out;
	}
	//msleep(50);
	memset(&chg_vif_info, 0, sizeof(chg_vif_info));
	chg_vif_info.state = WIFI_NRF_FMAC_IF_OP_STATE_UP;
	memcpy(chg_vif_info.ifacename, "wlan0", strlen("wlan0"));
	status = wifi_nrf_fmac_chg_vif_state(rpu_ctx, vif_ctx->vif_idx, &chg_vif_info);
	if (status != WIFI_NRF_STATUS_SUCCESS) {
		printk("%s: wifi_nrf_fmac_chg_vif_state failed\n",
			__func__);
		goto out;
	}

	msleep(100);
	//rpu_priv->vif_priv.dev = dev;

	status = wifi_nrf_fmac_get_wiphy(rpu_ctx, vif_ctx->vif_idx);
	if (status != WIFI_NRF_STATUS_SUCCESS) {
		printk("%s: nrf_wifi_fmac_get_wiphy failed\n", __func__);
	}

	return rpu_priv;

out:
	if (rpu_priv) {
		nrf_cfg80211_uninit(rpu_priv);
		rpu_priv = NULL;
	}
	return rpu_priv;
}

void wifi_nrf_fmac_dev_rem_lnx(struct wifi_nrf_rpu_priv_lnx *rpu_priv)
{
	if (!rpu_priv)
		return;
	wifi_nrf_fmac_dev_rem(rpu_priv->rpu_ctx);
	nrf_cfg80211_uninit(rpu_priv);
}

int nrf_wifi_init(void) {
#ifndef CONFIG_NRF700X_RADIO_TEST
	struct wifi_nrf_fmac_callbk_fns callbk_fns = { 0 };
	struct nrf_wifi_data_config_params data_config = { 0 };
	struct rx_buf_pool_params rx_buf_pools[MAX_NUM_OF_RX_QUEUES];

	if ((CONFIG_NRF700X_MAX_TX_TOKENS >= 1) &&
		(CONFIG_NRF700X_MAX_TX_AGGREGATION <= 15) &&
		(CONFIG_NRF700X_RX_NUM_BUFS >= 1) &&
		(RPU_PKTRAM_SIZE - TOTAL_RX_SIZE >= TOTAL_TX_SIZE)) {
		printk("Init config check ok: %d %d %d\n", RPU_PKTRAM_SIZE, TOTAL_RX_SIZE, TOTAL_TX_SIZE);
	} else {
		printk("Init config check fail\n");
		return -1;
	}

#ifdef CONFIG_NRF700X_DATA_TX
	data_config.aggregation = aggregation;
	data_config.wmm = wmm;
	data_config.max_num_tx_agg_sessions = max_num_tx_agg_sessions;
	data_config.max_num_rx_agg_sessions = max_num_rx_agg_sessions;
	data_config.max_tx_aggregation = max_tx_aggregation;
	data_config.reorder_buf_size = reorder_buf_size;
	data_config.max_rxampdu_size = max_rxampdu_size;
	data_config.rate_protection_type = rate_protection_type;

	callbk_fns.if_carr_state_chg_callbk_fn = wifi_nrf_if_carr_state_chg;
	callbk_fns.rx_frm_callbk_fn = nrf_wifi_umac_event_rx_frm_lnx;
#endif
	rx_buf_pools[0].num_bufs = rx1_num_bufs;
	rx_buf_pools[1].num_bufs = rx2_num_bufs;
	rx_buf_pools[2].num_bufs = rx3_num_bufs;
	rx_buf_pools[0].buf_sz = rx1_buf_sz;
	rx_buf_pools[1].buf_sz = rx2_buf_sz;
	rx_buf_pools[2].buf_sz = rx3_buf_sz;

	callbk_fns.event_get_wiphy = wifi_nrf_wpa_supp_event_get_wiphy_lnx;
	callbk_fns.scan_start_callbk_fn = wifi_nrf_wpa_supp_event_proc_scan_start_lnx;
	callbk_fns.scan_done_callbk_fn = wifi_nrf_wpa_supp_event_proc_scan_done_lnx;
	//callbk_fns.disp_scan_res_callbk_fn = nrf_wifi_umac_event_new_scan_display_results_lnx;
	//callbk_fns.twt_config_callbk_fn = wifi_nrf_event_proc_twt_setup_zep;
	//callbk_fns.twt_teardown_callbk_fn = wifi_nrf_event_proc_twt_teardown_zep;
	//callbk_fns.twt_sleep_callbk_fn = wifi_nrf_event_proc_twt_sleep_zep;
	//callbk_fns.event_get_reg = wifi_nrf_event_get_reg_zep;
#ifdef CONFIG_WPA_SUPP
	callbk_fns.scan_res_callbk_fn = wifi_nrf_wpa_supp_event_proc_scan_res_lnx;
	callbk_fns.auth_resp_callbk_fn = wifi_nrf_wpa_supp_event_proc_auth_resp_lnx;
	callbk_fns.assoc_resp_callbk_fn = wifi_nrf_wpa_supp_event_proc_assoc_resp_lnx;
	callbk_fns.deauth_callbk_fn = wifi_nrf_wpa_supp_event_proc_deauth_lnx;
	callbk_fns.disassoc_callbk_fn = wifi_nrf_wpa_supp_event_proc_disassoc_lnx;
	//callbk_fns.get_station_callbk_fn = wifi_nrf_wpa_supp_event_proc_get_sta;
	//callbk_fns.get_interface_callbk_fn = wifi_nrf_wpa_supp_event_proc_get_if;
	//callbk_fns.mgmt_tx_status = wifi_nrf_wpa_supp_event_mgmt_tx_status;
	//callbk_fns.unprot_mlme_mgmt_rx_callbk_fn = wifi_nrf_wpa_supp_event_proc_unprot_mgmt;
	//callbk_fns.mgmt_rx_callbk_fn = wifi_nrf_wpa_supp_event_mgmt_rx_callbk_fn;
#endif /* CONFIG_WPA_SUPP */
	rpu_drv_priv_lnx.fmac_priv = wifi_nrf_fmac_init(&data_config,
							rx_buf_pools,
							&callbk_fns);
#else /* !CONFIG_NRF700X_RADIO_TEST */
	rpu_drv_priv_lnx.fmac_priv = wifi_nrf_fmac_init();
#endif /* CONFIG_NRF700X_RADIO_TEST */

	if (rpu_drv_priv_lnx.fmac_priv == NULL) {
		printk("%s: wifi_nrf_fmac_init failed\n",
			__func__);
		goto err;
	}

#ifdef CONFIG_NRF700X_DATA_TX
	rpu_drv_priv_lnx.fmac_priv->max_ampdu_len_per_token =
		(RPU_PKTRAM_SIZE - (CONFIG_NRF700X_RX_NUM_BUFS * CONFIG_NRF700X_RX_MAX_DATA_SIZE)) /
		CONFIG_NRF700X_MAX_TX_TOKENS;
	/* Align to 4-byte */
	rpu_drv_priv_lnx.fmac_priv->max_ampdu_len_per_token &= ~0x3;

	/* Alignment overhead for size based coalesce */
	rpu_drv_priv_lnx.fmac_priv->avail_ampdu_len_per_token =
	rpu_drv_priv_lnx.fmac_priv->max_ampdu_len_per_token -
		(MAX_PKT_RAM_TX_ALIGN_OVERHEAD * max_tx_aggregation);
#endif /* CONFIG_NRF700X_DATA_TX */

	return 0;
		
err:
	return -1;
}

void nrf_wifi_exit(void) {
	wifi_nrf_fmac_deinit(rpu_drv_priv_lnx.fmac_priv);
}


