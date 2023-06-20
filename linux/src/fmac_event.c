#include "fmac_event.h"
#include "shim.h"
#include <linux_fmac_main.h>
#include <linux/slab.h>

void nrf_wifi_umac_event_trigger_scan_lnx(void *os_vif_ctx,
					struct nrf_wifi_umac_event_trigger_scan *trigger_scan_event,
					unsigned int event_len)
{
	struct fmac_event *event = NULL;
	struct nrf_vif_priv *vif_ctx = (struct nrf_vif_priv *)os_vif_ctx;
	ulong flags;

	event = kcalloc(sizeof(*event), sizeof(char), GFP_KERNEL);
	event->vif_ctx = os_vif_ctx;
	event->type = FMAC_EVENT_UMAC;
	event->data = kcalloc(event_len, sizeof(char), GFP_KERNEL);
	event->datalen = event_len;
	memcpy(event->data, trigger_scan_event, event_len);
	spin_lock_irqsave(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	list_add_tail(&event->q, vif_ctx->fmac_event_q);
	spin_unlock_irqrestore(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	schedule_work(&vif_ctx->rpu_priv->drv_priv->ws_event);
}

void nrf_wifi_umac_event_new_scan_display_results_lnx(void *os_vif_ctx,
				struct nrf_wifi_umac_event_new_scan_display_results *scan_res,
				unsigned int event_len,
				bool more_res)
{
	struct fmac_event *event = NULL;
	struct nrf_vif_priv *vif_ctx = (struct nrf_vif_priv *)os_vif_ctx;
	ulong flags;

	event = kcalloc(sizeof(*event), sizeof(char), GFP_KERNEL);
	event->vif_ctx = os_vif_ctx;
	event->type = FMAC_EVENT_UMAC;
	event->data = kcalloc(event_len, sizeof(char), GFP_KERNEL);
	event->datalen = event_len;
	memcpy(event->data, scan_res, event_len);
	spin_lock_irqsave(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	list_add_tail(&event->q, vif_ctx->fmac_event_q);
	spin_unlock_irqrestore(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	schedule_work(&vif_ctx->rpu_priv->drv_priv->ws_event);
}

void nrf_wifi_umac_event_new_scan_results_lnx(void *os_vif_ctx,
				   struct nrf_wifi_umac_event_new_scan_results *scan_res,
				   unsigned int event_len,
				   bool more_res)
{
	struct fmac_event *event = NULL;
	struct nrf_vif_priv *vif_ctx = (struct nrf_vif_priv *)os_vif_ctx;
	ulong flags;

	event = kcalloc(sizeof(*event), sizeof(char), GFP_KERNEL);
	event->type = FMAC_EVENT_UMAC;
	event->vif_ctx = os_vif_ctx;
	event->data = kcalloc(event_len, sizeof(char), GFP_KERNEL);
	event->datalen = event_len;
	memcpy(event->data, scan_res, event_len);
	spin_lock_irqsave(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	list_add_tail(&event->q, vif_ctx->fmac_event_q);
	spin_unlock_irqrestore(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	schedule_work(&vif_ctx->rpu_priv->drv_priv->ws_event);
}

void nrf_wifi_umac_event_mlme_lnx(void *os_vif_ctx,
						struct nrf_wifi_umac_event_mlme *mlme,
						unsigned int event_len)
{
	struct fmac_event *event = NULL;
	struct nrf_vif_priv *vif_ctx = (struct nrf_vif_priv *)os_vif_ctx;
	ulong flags;

	event = kcalloc(sizeof(*event), sizeof(char), GFP_KERNEL);
	event->vif_ctx = os_vif_ctx;
	event->type = FMAC_EVENT_UMAC;
	event->data = kcalloc(event_len, sizeof(char), GFP_KERNEL);
	event->datalen = event_len;
	memcpy(event->data, mlme, event_len);
	spin_lock_irqsave(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	list_add_tail(&event->q, vif_ctx->fmac_event_q);
	spin_unlock_irqrestore(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	schedule_work(&vif_ctx->rpu_priv->drv_priv->ws_event);
}

enum wifi_nrf_status nrf_wifi_umac_event_carr_state_chg_lnx(void *os_vif_ctx,
						enum wifi_nrf_fmac_if_carr_state carr_state)
{
	struct fmac_event *event = NULL;
	struct nrf_vif_priv *vif_ctx = (struct nrf_vif_priv *)os_vif_ctx;
	ulong flags;

	event = kcalloc(sizeof(*event), sizeof(char), GFP_KERNEL);
	event->type = FMAC_EVENT_CARR_STATE;
	event->vif_ctx = os_vif_ctx;
	event->data = kcalloc(sizeof(carr_state), sizeof(char), GFP_KERNEL);
	event->datalen = sizeof(carr_state);
	memcpy(event->data, &carr_state, event->datalen);
	spin_lock_irqsave(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	list_add_tail(&event->q, vif_ctx->fmac_event_q);
	spin_unlock_irqrestore(&vif_ctx->rpu_priv->drv_priv->evt_q_lock, flags);
	schedule_work(&vif_ctx->rpu_priv->drv_priv->ws_event);
	return WIFI_NRF_STATUS_SUCCESS;
}

void nrf_wifi_umac_event_rx_frm_lnx(void *os_vif_ctx, void *frm)
{
	struct nrf_vif_priv *vif_priv = NULL;
	struct sk_buff *skb;
	struct nwb *nwb;
	unsigned char *data;
	unsigned int len;

	if (!frm) {
		printk("%s frm is NULL\n", __func__);
		return;
	}
	nwb = frm;
	vif_priv = (struct nrf_vif_priv *)os_vif_ctx;

	len = nwb->len;
	data = nwb->data;

	if (len == 0) {
		printk("Zero frame length\n");
		return;
	}
	//printk("%s: len: %u\n", __func__, len);

	skb = dev_alloc_skb(len);
	if (!skb) {
		printk("Fail to allocate skb. Packet droped!\n");
		return;
	}
	memcpy(skb_put(skb, len), data, len);
	skb->dev = vif_priv->ndev;
	skb->protocol = eth_type_trans(skb, vif_priv->ndev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	netif_rx_ni(skb);
}