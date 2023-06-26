#include <stddef.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "shim.h"
#include "bal_api.h"

#include "osal_ops.h"

#if defined(CONFIG_NRF700X_ON_USB_ADAPTER)
#include "usb_request.h"
#endif

#include <linux/semaphore.h>

#define MAX_BULK_PACKET_SIZE 64

#if defined(CONFIG_NRF700X_ON_USB_ADAPTER)
static struct semaphore usb_lock;
static atomic_t tx_pending;
#define TX_MAX_PENDING_COUNT	10000
#endif

static void *lnx_shim_mem_alloc(size_t size)
{
	size = (size + 4) & 0xfffffffc;
	return kmalloc(size, GFP_KERNEL);
}

static void *lnx_shim_mem_zalloc(size_t size)
{
	size = (size + 4) & 0xfffffffc;
	return kcalloc(size, sizeof(char), GFP_KERNEL);
}

static void lnx_shim_mem_free(void *buf)
{
	if (buf == NULL)
		return;

	return kfree(buf);
}
#if defined(CONFIG_NRF700X_ON_QSPI)
static void lnx_shim_qspi_read_reg32_hl(struct spi_device *spi, void *dest, unsigned long addr)
{
	int ret;
	struct spi_message m;
	spi_message_init(&m);

	u8 extra_dummy_word = 3;
	u8 miso[64];
	u8 mosi[64];
	struct spi_transfer tr_hdr = {
		.tx_buf = mosi,
		.rx_buf = miso,
		.len = 1,
	};
	
	mosi[0] = 0x0B;
	mosi[1] = ((addr>>16)&0xFF);
	mosi[2] = (addr>>8)&0xFF;
	mosi[3] = addr&0xFF;
	mosi[4] = 0x00; //dummy byte
	memset(&mosi[5], 4 * extra_dummy_word, 0);
	tr_hdr.len = 5 + 4 * extra_dummy_word;
	spi_message_add_tail(&tr_hdr, &m);

	struct spi_transfer tr_payload = {
		.rx_buf = dest,
		.len = 4,
	};
	spi_message_add_tail(&tr_payload, &m);

	ret = spi_sync(spi, &m);
	if (ret < 0) {
		printk("error\n");
	}
}

static unsigned int lnx_shim_qspi_read_reg32(void *priv, unsigned long addr)
{
	struct lnx_shim_bus_qspi_priv *dev_priv = priv;
	int ret;
	struct spi_device *spi;
	u32 reg_val;

	spi = dev_priv->spi_dev;

	if (addr < 0x0C0000) {
		lnx_shim_qspi_read_reg32_hl(spi, &reg_val, addr);
		return reg_val;
	}

	u8 miso[64];
	u8 mosi[64];
	struct spi_transfer tr = {
		.tx_buf = mosi,
		.rx_buf = miso,
		.len = 1,
	};
		
	struct spi_message m;

	mosi[0] = 0x0B;
	mosi[1] = (addr>>16)&0xFF;
	mosi[2] = (addr>>8)&0xFF;
	mosi[3] = addr&0xFF;
	mosi[4] = 0x00; //dummy byte
	tr.len = 9;
	spi_message_init(&m);
	spi_message_add_tail(&tr, &m);
	ret = spi_sync(spi, &m);
	if (ret < 0) {
		printk("error\n");
		return -1;
	}

	reg_val = miso[5] + (miso[6] << 8) + (miso[7] << 16) + (miso[8] << 24);
	return reg_val;
}

static void lnx_shim_qspi_write_reg32(void *priv, unsigned long addr, unsigned int val)
{
	struct lnx_shim_bus_qspi_priv *dev_priv = priv;
	int ret;
	struct spi_device *spi;

	spi = dev_priv->spi_dev;

	u8 miso[64];
	u8 mosi[64];
	struct spi_transfer tr = {
		.tx_buf = mosi,
		.rx_buf = miso,
		.len = 1,
	};
		
	struct spi_message m;

	mosi[0] = 0x02;
	mosi[1] = ((addr>>16)&0xFF) | 0x80;
	mosi[2] = (addr>>8)&0xFF;
	mosi[3] = addr&0xFF;
	mosi[4] = val & 0xFF;
	mosi[5] = (val >> 8) & 0xFF;
	mosi[6] = (val >> 16) & 0xFF;
	mosi[7] = (val >> 24) & 0xFF;
	tr.len = 8;
	spi_message_init(&m);
	spi_message_add_tail(&tr, &m);
	ret = spi_sync(spi, &m);
	if (ret < 0) {
		printk("error\n");
	}
}

static void lnx_shim_qspi_cpy_from(void *priv, void *dest, unsigned long addr, size_t count)
{
	struct lnx_shim_bus_qspi_priv *dev_priv = priv;
	int ret;
	struct spi_device *spi;

	spi = dev_priv->spi_dev;

	if(count % 4 != 0) {
		count = (count + 4) & 0xFFFFFFFC;
	}

	if (addr < 0x0C0000) {
		int offset = 0;
		while (count > 0) {
			lnx_shim_qspi_read_reg32_hl(spi, dest + offset, addr + offset);
			offset += 4;
			count -= 4;
		}
		return;
	}

	struct spi_message m;
	spi_message_init(&m);

	u8 miso[64];
	u8 mosi[64];
	struct spi_transfer tr_hdr = {
		.tx_buf = mosi,
		.rx_buf = miso,
		.len = 1,
	};
	
	mosi[0] = 0x0B;
	mosi[1] = ((addr>>16)&0xFF) | 0x80;
	mosi[2] = (addr>>8)&0xFF;
	mosi[3] = addr&0xFF;
	mosi[4] = 0x00; //dummy byte
	tr_hdr.len = 5;
	spi_message_add_tail(&tr_hdr, &m);

	struct spi_transfer tr_payload = {
		.rx_buf = dest,
		.len = count,
	};
	spi_message_add_tail(&tr_payload, &m);

	ret = spi_sync(spi, &m);
	if (ret < 0) {
		printk("error\n");
	}
}

static void lnx_shim_qspi_cpy_to(void *priv, unsigned long addr, const void *src, size_t count)
{
	struct lnx_shim_bus_qspi_priv *dev_priv = priv;
	int ret;
	struct spi_device *spi;

	spi = dev_priv->spi_dev;

	if(count % 4 != 0) {
		count = (count + 4) & 0xFFFFFFFC;
	}

	struct spi_message m;
	spi_message_init(&m);

	u8 miso[64];
	u8 mosi[64];
	struct spi_transfer tr_hdr = {
		.tx_buf = mosi,
		.rx_buf = miso,
		.len = 1,
	};
	
	mosi[0] = 0x02;
	mosi[1] = ((addr>>16)&0xFF) | 0x80;
	mosi[2] = (addr>>8)&0xFF;
	mosi[3] = addr&0xFF;
	tr_hdr.len = 4;
	spi_message_add_tail(&tr_hdr, &m);

	struct spi_transfer tr_payload = {
		.tx_buf = src,
		.len = count,
	};
	spi_message_add_tail(&tr_payload, &m);

	ret = spi_sync(spi, &m);
	if (ret < 0) {
		printk("error\n");
	}
}
#endif
#if defined(CONFIG_NRF700X_ON_USB_ADAPTER)
static void usb_send_ctrl_cb(struct urb *urb)
{
	if (urb) {
		if (urb->status != 0) {
			printk("%s: status: %d\n", __func__, urb->status);
		}
	}
	atomic_set(&tx_pending, 0);
}

static void usb_recv_ctrl_cb(struct urb *urb)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv;
	if (urb) {
		if (urb->status != 0) {
			printk("%s: status: %d\n", __func__, urb->status);
		}
		qspi_priv = (struct lnx_shim_bus_qspi_priv *)urb->context;
		qspi_priv->actual_length = urb->actual_length;
	}
	atomic_set(&tx_pending, 0);
}

static void usb_send_bulk_cb(struct urb *urb)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv;

	if (urb) {
		if (urb->status != 0) {
			printk("%s: status: %d\n", __func__, urb->status);
		}
		qspi_priv = (struct lnx_shim_bus_qspi_priv *)urb->context;
		qspi_priv->actual_length = urb->actual_length;
	}
	atomic_set(&tx_pending, 0);
}

static void usb_recv_bulk_cb(struct urb *urb)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv;

	if (urb) {
		if (urb->status != 0) {
			printk("%s: status: %d\n", __func__, urb->status);
		}
		qspi_priv = (struct lnx_shim_bus_qspi_priv *)urb->context;
		qspi_priv->actual_length = urb->actual_length;
	}
	atomic_set(&tx_pending, 0);
}

static int usb_send_ctrl(struct lnx_shim_bus_qspi_priv *qspi_priv, void *buf, u16 len)
{
	int ret, timeout;

	if (qspi_priv == NULL || buf == NULL || len == 0 || qspi_priv->usbdev == NULL)
		return -EINVAL;

	qspi_priv->ctrl_write.bRequestType = USB_TYPE_VENDOR | USB_DIR_OUT | USB_RECIP_DEVICE;
	qspi_priv->ctrl_write.bRequest = REGISTER_WRITE;
	qspi_priv->ctrl_write.wIndex = 0;
	qspi_priv->ctrl_write.wValue = 0;
	qspi_priv->ctrl_write.wLength = cpu_to_le16(len);
	usb_fill_control_urb(qspi_priv->ctrl_urb,
		qspi_priv->usbdev,
		usb_sndctrlpipe(qspi_priv->usbdev, 0),
		(unsigned char *) &qspi_priv->ctrl_write,
		buf, len,
		usb_send_ctrl_cb,
		NULL);

	atomic_set(&tx_pending, 1);
	ret = usb_submit_urb(qspi_priv->ctrl_urb, GFP_ATOMIC);
	if (ret < 0) {
		printk("usb_submit_urb failed %d\n", ret);
		goto out;
	}
	timeout = 0;
	while (timeout <= TX_MAX_PENDING_COUNT) {
		if (atomic_read(&tx_pending) == 0) {
			break;
		}
		udelay(10);
		timeout++;
	}
	if (timeout > TX_MAX_PENDING_COUNT) {
		ret = -ETIMEDOUT;
	} else {
		ret = 0;
	}
out:
	return ret;
}

static int usb_recv_ctrl(struct lnx_shim_bus_qspi_priv *qspi_priv, void *buf, u16 len)
{
	int ret, timeout;

	if (qspi_priv == NULL || buf == NULL || len == 0 || qspi_priv->usbdev == NULL)
		return -EINVAL;

	qspi_priv->ctrl_read.bRequestType = USB_TYPE_VENDOR | USB_DIR_IN | USB_RECIP_DEVICE;
	qspi_priv->ctrl_read.bRequest = REGISTER_READ;
	qspi_priv->ctrl_read.wIndex = 0;
	qspi_priv->ctrl_read.wValue = 0;
	qspi_priv->ctrl_read.wLength = cpu_to_le16(len);
	usb_fill_control_urb(qspi_priv->ctrl_urb,
		qspi_priv->usbdev,
		usb_rcvctrlpipe(qspi_priv->usbdev, 0),
		(unsigned char *) &qspi_priv->ctrl_read,
		buf, len,
		usb_recv_ctrl_cb,
		qspi_priv);

	atomic_set(&tx_pending, 1);
	ret = usb_submit_urb(qspi_priv->ctrl_urb, GFP_ATOMIC);
	if (ret < 0) {
		printk("usb_submit_urb failed %d\n", ret);
		goto out;
	}
	timeout = 0;
	while (timeout <= TX_MAX_PENDING_COUNT) {
		if (atomic_read(&tx_pending) == 0) {
			break;
		}
		udelay(10);
		timeout++;
	}
	if (timeout > TX_MAX_PENDING_COUNT) {
		ret = -ETIMEDOUT;
	} else {
		ret = 0;
	}
out:
	return ret;
}

static int usb_send_bulk(struct lnx_shim_bus_qspi_priv *qspi_priv, void *buf, u16 len)
{
	int ret, timeout;

	if (qspi_priv == NULL || buf == NULL || len == 0 || qspi_priv->usbdev == NULL)
		return -EINVAL;

	usb_fill_bulk_urb(qspi_priv->bulk_urb,
		qspi_priv->usbdev,
		usb_sndbulkpipe(qspi_priv->usbdev, 1),
		buf, len,
		usb_send_bulk_cb,
		qspi_priv);
	qspi_priv->bulk_urb->transfer_flags |= URB_ZERO_PACKET;
	atomic_set(&tx_pending, 1);
	ret = usb_submit_urb(qspi_priv->bulk_urb, GFP_ATOMIC);
	if (ret < 0) {
		printk("usb_submit_urb failed %d\n", ret);
		goto out;
	}
	timeout = 0;
	while (timeout <= TX_MAX_PENDING_COUNT) {
		if (atomic_read(&tx_pending) == 0) {
			break;
		}
		udelay(10);
		timeout++;
	}
	if (timeout > TX_MAX_PENDING_COUNT) {
		ret = -ETIMEDOUT;
	} else {
		ret = 0;
	}
out:
	return ret;
}

static int usb_recv_bulk(struct lnx_shim_bus_qspi_priv *qspi_priv, void *buf, u16 len)
{
	int ret, timeout;

	if (qspi_priv == NULL || buf == NULL || len == 0 || qspi_priv->usbdev == NULL)
		return -EINVAL;

	usb_fill_bulk_urb(qspi_priv->bulk_rx_urb,
		qspi_priv->usbdev,
		usb_rcvbulkpipe(qspi_priv->usbdev, 1),
		buf, len,
		usb_recv_bulk_cb,
		qspi_priv);
	atomic_set(&tx_pending, 1);
	ret = usb_submit_urb(qspi_priv->bulk_rx_urb, GFP_ATOMIC);
	if (ret < 0) {
		printk("usb_submit_urb failed %d\n", ret);
		goto out;
	}
	timeout = 0;
	while (timeout <= TX_MAX_PENDING_COUNT) {
		if (atomic_read(&tx_pending) == 0) {
			break;
		}
		udelay(10);
		timeout++;
	}
	if (timeout > TX_MAX_PENDING_COUNT) {
		ret = -ETIMEDOUT;
	} else {
		ret = 0;
	}
out:
	return ret;
}

static unsigned int lnx_shim_usb_read_reg32(void *priv, unsigned long addr)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv = priv;
	int ret;
	struct rpu_request *req;
	u8 *buf = NULL;
	uint32_t val;

	down(&usb_lock);

	req = kcalloc(sizeof(*req), sizeof(char), GFP_KERNEL);
	if (!req) {
		printk("%s: Unable to allocate memory\n", __func__);
		return 0xFFFFFFFF;
	}
	req->cmd = REGISTER_READ;
	req->read_reg.addr = (uint32_t)addr;

	ret = usb_send_ctrl(qspi_priv, (void *)req, sizeof(*req));
	kfree(req);
	if (ret != 0) {
		printk("Fail to send control message: %d\n", ret);
		up(&usb_lock);
		return 0xFFFFFFFF;
	}

	buf = kcalloc(sizeof(val), sizeof(char), GFP_KERNEL);
retry:
	ret = usb_recv_ctrl(qspi_priv, (void *)buf, sizeof(val));
	if (ret != 0) {
		printk("Fail to recv control message: %d\n", ret);
		val = 0xFFFFFFFF;
	} else {
		if (qspi_priv->actual_length != sizeof(val)) {
			goto retry;
		}
		val = *(uint32_t *)buf;
	}
	kfree(buf);
	up(&usb_lock);

	return val;
}

static void lnx_shim_usb_write_reg32(void *priv, unsigned long addr, unsigned int val)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv = priv;
	int ret;
	struct rpu_request *req;

	down(&usb_lock);

	req = kcalloc(sizeof(*req), sizeof(char), GFP_KERNEL);
	if (!req) {
		printk("%s: Unable to allocate memory\n", __func__);
		up(&usb_lock);
		return;
	}

	req->cmd = REGISTER_WRITE;
	req->write_reg.addr = (uint32_t)addr;
	req->write_reg.val = val;

	ret = usb_send_ctrl(qspi_priv, (void *)req, sizeof(*req));
	if (ret != 0) {
		printk("Fail to send control message: %d\n", ret);
	}
	kfree(req);

	up(&usb_lock);
	return;
}

static void lnx_shim_usb_cpy_from(void *priv, void *dest, unsigned long addr, size_t count)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv = priv;
	struct rpu_request *req;
	int ret, offset, retry_cnt;
	void *buf;

	if (count % 4 != 0) {
		count = (count + 4) & 0xfffffffc;
	}

	down(&usb_lock);

	//usleep_range(100, 200);
	//TO check: is destination allocated as aligned count?
	req = kcalloc(sizeof(*req), sizeof(char), GFP_KERNEL);
	if (!req) {
		printk("%s: Unable to allocate memory\n", __func__);
		up(&usb_lock);
		return;
	}
	req->cmd = BLOCK_READ;
	req->read_block.addr = (uint32_t)addr;
	req->read_block.count = (int32_t)count;
	ret = usb_send_bulk(qspi_priv, req, sizeof(*req));
	if (ret || (qspi_priv->actual_length != sizeof(*req))) {
		printk("%s: Unable to send usb bulk msg: %d\n", __func__, ret);
	}
	kfree(req);
	buf = kcalloc((int32_t)count, sizeof(char), GFP_KERNEL);
	if (!buf) {
		printk("%s: Unable to allocate memory\n", __func__);
		up(&usb_lock);
		return;
	}
	offset = 0;
	retry_cnt = 0;
	while (count - offset > 0) {
		ret = usb_recv_bulk(qspi_priv, buf + offset, MAX_BULK_PACKET_SIZE);
		if (ret) {
			retry_cnt++;
			if(retry_cnt > 100) {
				printk("%s %u %d actual_length: %u\n", __func__, __LINE__, ret, qspi_priv->actual_length);
				goto out;
			}
		}
		offset += qspi_priv->actual_length;
	}
	memcpy(dest, buf, count);
out:
	kfree(buf);
	up(&usb_lock);
}

static void lnx_shim_usb_cpy_to(void *priv, unsigned long addr, const void *src, size_t count)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv = priv;
	struct rpu_request req;
	int ret, retry_cnt;
	void *buf;
	uint32_t offset = 0;

	if (count % 4 != 0) {
		count = (count + 4) & 0xfffffffc;
	}

	down(&usb_lock);
	buf = kcalloc(MAX_BULK_PACKET_SIZE, sizeof(char), GFP_KERNEL);
	if (!buf) {
		printk("%s: Unable to allocate memory\n", __func__);
		up(&usb_lock);
		return;
	}
	req.cmd = BLOCK_WRITE;
	retry_cnt = 0;
	while ((int32_t)count - offset > 0) {
		req.write_block.addr = (uint32_t)addr + offset;
		req.write_block.count = (((int32_t)count - offset) > (MAX_BULK_PACKET_SIZE - sizeof(req)))?(MAX_BULK_PACKET_SIZE - sizeof(req)):((int32_t)count - offset);
		memcpy(buf, &req, sizeof(req));
		memcpy(buf + sizeof(req), src + offset, req.write_block.count);
		ret = usb_send_bulk(qspi_priv, buf, sizeof(req) + req.write_block.count);
		if (ret || (qspi_priv->actual_length != sizeof(req) + req.write_block.count)) {
			retry_cnt++;
			if(retry_cnt > 100) {
				printk("%s: Unable to send usb bulk msg: %d\n", __func__, ret);
				goto out;
			}
		}
		offset += req.write_block.count;
	}
out:
	kfree(buf);
	up(&usb_lock);
}
#endif
static void *lnx_shim_spinlock_alloc(void)
{
	struct semaphore *lock;

	lock = kmalloc(sizeof(*lock), GFP_KERNEL);
	if (!lock) {
		printk("%s: Unable to allocate memory for spinlock\n", __func__);
	}

	return lock;
}

static void lnx_shim_spinlock_free(void *lock)
{
	kfree(lock);
}

static void lnx_shim_spinlock_init(void *lock)
{
	sema_init((struct semaphore *)lock, 1);
}

static void lnx_shim_spinlock_take(void *lock)
{
	down((struct semaphore *)lock);
}

static void lnx_shim_spinlock_rel(void *lock)
{
	up((struct semaphore *)lock);
}

static void lnx_shim_spinlock_irq_take(void *lock, unsigned long *flags)
{
	down((struct semaphore *)lock);
}

static void lnx_shim_spinlock_irq_rel(void *lock, unsigned long *flags)
{
	up((struct semaphore *)lock);
}

static int lnx_shim_pr_dbg(const char *fmt, va_list args)
{
/*
	char buf[256];

	vsnprintf(buf, sizeof(buf), fmt, args);

	printk(KERN_DEBUG "%s\n", buf);
*/
	return 0;
}

static int lnx_shim_pr_info(const char *fmt, va_list args)
{
	char buf[256];

	vsnprintf(buf, sizeof(buf), fmt, args);

	printk(KERN_INFO "%s\n", buf);

	return 0;
}

static int lnx_shim_pr_err(const char *fmt, va_list args)
{
	char buf[256];

	vsnprintf(buf, sizeof(buf), fmt, args);

	printk(KERN_ERR "%s\n", buf);

	return 0;
}

static void *lnx_shim_nbuf_alloc(unsigned int size)
{
	struct nwb *nwb;

	nwb = (struct nwb *)kcalloc(sizeof(struct nwb), sizeof(char), GFP_KERNEL);

	if (!nwb)
		return NULL;

	nwb->priv = kcalloc(size, sizeof(char), GFP_KERNEL);

	if (!nwb->priv) {
		kfree(nwb);
		return NULL;
	}

	nwb->data = (unsigned char *)nwb->priv;
	nwb->tail = nwb->data;
	nwb->len = 0;
	nwb->headroom = 0;
	nwb->next = NULL;

	return nwb;
}

static void lnx_shim_nbuf_free(void *nbuf)
{
	struct nwb *nwb;

	nwb = nbuf;

	kfree(((struct nwb *)nbuf)->priv);

	kfree(nbuf);
}

static void lnx_shim_nbuf_headroom_res(void *nbuf, unsigned int size)
{
	struct nwb *nwb = (struct nwb *)nbuf;

	nwb->data += size;
	nwb->tail += size;
	nwb->headroom += size;
}

static unsigned int lnx_shim_nbuf_headroom_get(void *nbuf)
{
	return ((struct nwb *)nbuf)->headroom;
}

static unsigned int lnx_shim_nbuf_data_size(void *nbuf)
{
	return ((struct nwb *)nbuf)->len;
}

static void *lnx_shim_nbuf_data_get(void *nbuf)
{
	return ((struct nwb *)nbuf)->data;
}

static void *lnx_shim_nbuf_data_put(void *nbuf, unsigned int size)
{
	struct nwb *nwb = (struct nwb *)nbuf;
	unsigned char *data = nwb->tail;

	nwb->tail += size;
	nwb->len += size;

	return data;
}

static void *lnx_shim_nbuf_data_push(void *nbuf, unsigned int size)
{
	struct nwb *nwb = (struct nwb *)nbuf;

	nwb->data -= size;
	nwb->headroom -= size;
	nwb->len += size;

	return nwb->data;
}

static void *lnx_shim_nbuf_data_pull(void *nbuf, unsigned int size)
{
	struct nwb *nwb = (struct nwb *)nbuf;

	nwb->data += size;
	nwb->headroom += size;
	nwb->len -= size;

	return nwb->data;
}

void *net_pkt_to_nbuf(struct sk_buff *skb)
{
	struct nwb *nwb;

	unsigned char *data;
	unsigned int len;

	len = skb->len;

	nwb = lnx_shim_nbuf_alloc(len + 100);

	if (!nwb) {
		printk("%s: Fail to allocate nwb\n", __func__);
		return NULL;
	}

	lnx_shim_nbuf_headroom_res(nwb, 100);

	data = lnx_shim_nbuf_data_put(nwb, len);
	memcpy(data, skb->data, len);

	return nwb;
}

static void *lnx_shim_llist_node_alloc(void)
{
	struct lnx_shim_llist_node *llist_node = NULL;

	llist_node = kcalloc(sizeof(*llist_node), sizeof(char), GFP_KERNEL);

	if (!llist_node) {
		printk("%s: Unable to allocate memory for linked list node\n", __func__);
		return NULL;
	}

	INIT_LIST_HEAD(&llist_node->list);

	return llist_node;
}

static void lnx_shim_llist_node_free(void *llist_node)
{
	kfree(llist_node);
}

static void *lnx_shim_llist_node_data_get(void *llist_node)
{
	struct lnx_shim_llist_node *lnx_llist_node = NULL;

	lnx_llist_node = (struct lnx_shim_llist_node *)llist_node;

	return lnx_llist_node->data;
}

static void lnx_shim_llist_node_data_set(void *llist_node, void *data)
{
	struct lnx_shim_llist_node *lnx_llist_node = NULL;

	lnx_llist_node = (struct lnx_shim_llist_node *)llist_node;

	lnx_llist_node->data = data;
}

static void *lnx_shim_llist_alloc(void)
{
	struct lnx_shim_llist *llist = NULL;

	llist = kcalloc(sizeof(*llist), sizeof(char), GFP_KERNEL);
	if (!llist) {
		printk("%s: Unable to allocate memory for linked list\n", __func__);
	}

	return llist;
}

static void lnx_shim_llist_free(void *llist)
{
	kfree(llist);
}

static void lnx_shim_llist_init(void *llist)
{
	struct lnx_shim_llist *lnx_llist = NULL;

	lnx_llist = (struct lnx_shim_llist *)llist;
	INIT_LIST_HEAD(&lnx_llist->list);
	lnx_llist->len = 0;
}

static void lnx_shim_llist_add_node_tail(void *llist, void *llist_node)
{
	struct lnx_shim_llist *lnx_llist = NULL;
	struct lnx_shim_llist_node *lnx_node = NULL;

	lnx_llist = (struct lnx_shim_llist *)llist;
	lnx_node = (struct lnx_shim_llist_node *)llist_node;

	list_add_tail(&lnx_node->list, &lnx_llist->list);
	lnx_llist->len += 1;
}

static void *lnx_shim_llist_get_node_head(void *llist)
{
	struct lnx_shim_llist_node *lnx_head_node = NULL;
	struct lnx_shim_llist *lnx_llist = NULL;

	lnx_llist = (struct lnx_shim_llist *)llist;

	if (!lnx_llist->len) {
		return NULL;
	}

	lnx_head_node = (struct lnx_shim_llist_node *)container_of(lnx_llist->list.next,
									   struct lnx_shim_llist_node,
									   list);

	return lnx_head_node;
}

static void *lnx_shim_llist_get_node_nxt(void *llist, void *llist_node)
{
	struct lnx_shim_llist_node *lnx_node = NULL;
	struct lnx_shim_llist_node *lnx_nxt_node = NULL;
	struct lnx_shim_llist *lnx_llist = NULL;

	lnx_llist = (struct lnx_shim_llist *)llist;
	lnx_node = (struct lnx_shim_llist_node *)llist_node;

	if (lnx_node->list.next == &lnx_llist->list)
		return NULL;

	lnx_nxt_node = (struct lnx_shim_llist_node *)container_of(lnx_node->list.next,
									  struct lnx_shim_llist_node,
									  list);

	return lnx_nxt_node;
}

static void lnx_shim_llist_del_node(void *llist, void *llist_node)
{
	struct lnx_shim_llist_node *lnx_node = NULL;
	struct lnx_shim_llist *lnx_llist = NULL;

	lnx_llist = (struct lnx_shim_llist *)llist;
	lnx_node = (struct lnx_shim_llist_node *)llist_node;

	list_del(&lnx_node->list);
	lnx_llist->len -= 1;
}

static unsigned int lnx_shim_llist_len(void *llist)
{
	struct lnx_shim_llist *lnx_llist = NULL;

	lnx_llist = (struct lnx_shim_llist *)llist;

	return lnx_llist->len;
}

static void *lnx_shim_work_alloc(int type)
{
	struct work_item *item = NULL;

	item = kcalloc(sizeof(*item), sizeof(char), GFP_KERNEL);

	if (!item) {
		printk("%s: Unable to allocate memory for work\n", __func__);
		goto out;
	}
out:
	return item;
}

static void lnx_shim_work_free(void *item)
{
	return kfree(item);
}

static void fn_worker(struct work_struct *worker)
{
	struct work_item *item_ctx;

	item_ctx = container_of(worker, struct work_item, work);
	item_ctx->callback(item_ctx->data);
}

static void lnx_shim_work_init(void *item, void (*callback)(unsigned long data),
				  unsigned long data)
{
	struct work_item *item_ctx = NULL;

	item_ctx = item;
	item_ctx->data = data;
	item_ctx->callback = callback;
	INIT_WORK(&item_ctx->work, fn_worker);
}

static void lnx_shim_work_schedule(void *item)
{
	struct work_item *item_ctx = NULL;

	item_ctx = item;
	schedule_work(&item_ctx->work);
}

static void lnx_shim_work_kill(void *item)
{
	struct work_item *item_ctx = NULL;

	item_ctx = item;
	cancel_work_sync(&item_ctx->work);
}

static int lnx_shim_msleep(int msecs)
{
	msleep((unsigned int)msecs);

	return 0;
}

static int lnx_shim_usleep(int usecs)
{
	usleep_range((unsigned int)usecs, (unsigned int)(usecs * 2));

	return 0;
}

static unsigned long lnx_shim_time_get_curr_us(void)
{
	return ktime_to_us(ktime_get_boottime());
}

static unsigned int lnx_shim_time_elapsed_us(unsigned long start_time_us)
{
	unsigned long curr_time_us = 0;

	curr_time_us = lnx_shim_time_get_curr_us();

	return curr_time_us - start_time_us;
}

static enum wifi_nrf_status lnx_shim_bus_qspi_dev_init(void *os_qspi_dev_ctx)
{
	enum wifi_nrf_status status = WIFI_NRF_STATUS_FAIL;
	struct qspi_dev *dev = NULL;

	dev = os_qspi_dev_ctx;

	status = WIFI_NRF_STATUS_SUCCESS;

	return status;
}

static void lnx_shim_bus_qspi_dev_deinit(void *os_qspi_dev_ctx)
{
	struct qspi_dev *dev = NULL;

	dev = os_qspi_dev_ctx;
}

#if defined(CONFIG_NRF700X_ON_QSPI)
static void *lnx_shim_bus_spi_init(void)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv = NULL;

	qspi_priv = kcalloc(sizeof(*qspi_priv), sizeof(char), GFP_KERNEL);

	if (!qspi_priv) {
		printk("%s: Unable to allocate memory for qspi_priv\n", __func__);
		goto out;
	}
out:
	return qspi_priv;
}

static void lnx_shim_bus_spi_deinit(void *os_qspi_priv)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv = NULL;

	qspi_priv = os_qspi_priv;

	kfree(qspi_priv);
}

void print_spi_transaction(__u8 *miso, __u8 *mosi, __u32 length)
{
	int i;

	printk("MOSI  MISO\n");
	for (i = 0; i < length; i++)
		printk("%.2X  : %.2X\n", mosi[i], miso[i]);
}

static void *lnx_shim_bus_spi_dev_add(void *os_qspi_priv, void *osal_qspi_dev_ctx)
{
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = NULL;
	int ret;
	lnx_qspi_priv = os_qspi_priv;
	int i = 0;

	u8 miso[64];
	u8 mosi[64];
	struct spi_transfer tr = {
		.tx_buf = mosi,
		.rx_buf = miso,
		.len = 1,
	};

	struct spi_message m;

	// set up wq for ISR work
	lnx_qspi_priv->wq = alloc_workqueue("nRF7002 WQ", 0, 1);
	if (lnx_qspi_priv->wq == NULL) {
		printk("Cannot allocate WQ\n");
		return NULL;
	}

	//get BUCKEN and IOVDD gpio pins
	if(!device_property_present(&lnx_qspi_priv->spi_dev->dev, "iovdd-gpio")) {
		printk("dt_gpio - Error! Device property 'iovdd-gpio' not found!\n");
		return NULL;
	}

	lnx_qspi_priv->iovdd = devm_gpiod_get(&lnx_qspi_priv->spi_dev->dev, "iovdd", 0);
	if (IS_ERR(lnx_qspi_priv->iovdd)) {
		printk("Cannot get iovdd gpio handle\n");
		return NULL;
	} 

	ret = gpiod_direction_output(lnx_qspi_priv->iovdd, 0);
	if (ret < 0) {
		printk("Cannot set iovdd gpio direction\n");
		return NULL;
	} else {
		printk("Set iovdd direction out\n");
	}

	lnx_qspi_priv->bucken = devm_gpiod_get(&lnx_qspi_priv->spi_dev->dev, "bucken", 0);
	if (IS_ERR(lnx_qspi_priv->bucken)) {
		printk("Cannot get bucken gpio handle\n");
		return NULL;
	} 

	ret = gpiod_direction_output(lnx_qspi_priv->bucken, 0);
	if (ret < 0) {
		printk("Cannot set bucken gpio direction\n");
		return NULL;
	} else {
		printk("Set bucken direction out\n");
	}

	lnx_qspi_priv->host_irq = devm_gpiod_get(&lnx_qspi_priv->spi_dev->dev, "irq", 0);
	if (IS_ERR(lnx_qspi_priv->host_irq)) {
		printk("Cannot get irq gpio handle\n");
		return NULL;
	} 

	ret = gpiod_direction_input(lnx_qspi_priv->host_irq);
	if (ret < 0) {
		printk("Cannot set irq gpio direction\n");
	return NULL;
	} else {
		printk("Set irq direction in\n");
	}

	lnx_qspi_priv->host_irq = lnx_qspi_priv->host_irq;

	//Rise BUCKEN and IOVDD
	gpiod_set_value(lnx_qspi_priv->bucken, 0);
	gpiod_set_value(lnx_qspi_priv->iovdd, 0);
	msleep(100);
	gpiod_set_value(lnx_qspi_priv->bucken, 1);
	msleep(100);
	gpiod_set_value(lnx_qspi_priv->iovdd, 1);
	msleep(100);
	// Send 0x3F, 0x01

	mosi[0] = 0x3F;
	mosi[1] = 0x01;
	tr.len = 2;
	spi_message_init(&m);
	spi_message_add_tail(&tr, &m);
	ret = spi_sync(lnx_qspi_priv->spi_dev, &m);
	if (ret == -1) {
		printk("error\n");
		return NULL;
	}
	msleep(1000);
	//Read the reg by sending 0x2F
	for (i = 0; i < 10; i++) {
		mosi[0] = 0x2F;
		tr.len = 6;
		spi_message_init(&m);
		spi_message_add_tail(&tr, &m);
		ret = spi_sync(lnx_qspi_priv->spi_dev, &m);
		if (ret < 0) {
			printk("error\n");
			return NULL;
		}
		print_spi_transaction(miso, mosi, tr.len);
		if (miso[1] & (1<<0)) {
			printk("RDSR2 successful\n");
			break;
		}
		msleep(10);
	}
	//Read the reg by sending 0x1F
	for (i = 0; i < 10; i++) {
		mosi[0] = 0x1F;
		tr.len = 6;
		spi_message_init(&m);
		spi_message_add_tail(&tr, &m);
		ret = spi_sync(lnx_qspi_priv->spi_dev, &m);
		if (ret < 0) {
			printk("error\n");
			return NULL;
		}
		print_spi_transaction(miso, mosi, tr.len);
		if (miso[1] & (1<<1)) {
			printk("RDSR1 successful\n");
			break;
		}
	msleep(10);
	}
	// Write 0x100 to 0x048C20 to start the clock
	mosi[0] = 0x02;
	mosi[1] = 0x04 | 0x80;
	mosi[2] = 0x8C;
	mosi[3] = 0x20;
	mosi[4] = 0x00;
	mosi[5] = 0x01;
	mosi[6] = 0x00;
	mosi[7] = 0x00;
	tr.len = 8;
	spi_message_init(&m);
	spi_message_add_tail(&tr, &m);
	ret = spi_sync(lnx_qspi_priv->spi_dev, &m);
	if (ret == -1) {
		printk("error\n");
		return NULL;
	}

	lnx_qspi_priv->dev_added = true;

	return lnx_qspi_priv;
}

static void lnx_shim_bus_spi_dev_rem(void *os_qspi_dev_ctx)
{
	struct qspi_dev *dev = NULL;
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = NULL;

	dev = os_qspi_dev_ctx;
	lnx_qspi_priv = os_qspi_dev_ctx;

	if (lnx_qspi_priv->wq) {
		destroy_workqueue(lnx_qspi_priv->wq);
	}
	/* Send control msg to remove Wi-Fi device */

	/* TODO: Make qspi_dev a dynamic instance and remove it here */
}

#endif

#if defined(CONFIG_NRF700X_ON_USB_ADAPTER)
static void *lnx_shim_bus_usb_init(void)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv = NULL;

	sema_init(&usb_lock, 1);

	qspi_priv = kcalloc(sizeof(*qspi_priv), sizeof(char), GFP_KERNEL);

	if (!qspi_priv) {
		printk("%s: Unable to allocate memory for qspi_priv\n", __func__);
		goto out;
	}

	qspi_priv->ctrl_urb = usb_alloc_urb(0, GFP_KERNEL);
	qspi_priv->bulk_urb = usb_alloc_urb(0, GFP_KERNEL);
	qspi_priv->bulk_rx_urb = usb_alloc_urb(0, GFP_KERNEL);

out:
	return qspi_priv;
}

static void lnx_shim_bus_usb_deinit(void *os_qspi_priv)
{
	struct lnx_shim_bus_qspi_priv *qspi_priv = NULL;

	qspi_priv = os_qspi_priv;
	if (qspi_priv->ctrl_urb)
		usb_free_urb(qspi_priv->ctrl_urb);

	if (qspi_priv->bulk_urb)
		usb_free_urb(qspi_priv->bulk_urb);

	if (qspi_priv->bulk_rx_urb)
		usb_free_urb(qspi_priv->bulk_rx_urb);

	kfree(qspi_priv);
}

static void *lnx_shim_bus_usb_dev_add(void *os_qspi_priv, void *osal_qspi_dev_ctx)
{
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = NULL;
	u32 size;
	int ret;

	lnx_qspi_priv = os_qspi_priv;

	/* Send control msg to add Wi-Fi device */
	ret = usb_control_msg(lnx_qspi_priv->usbdev,
				  usb_sndctrlpipe(lnx_qspi_priv->usbdev, 0),
				  RPU_ENABLE,
				  USB_TYPE_VENDOR | USB_DIR_OUT | USB_RECIP_DEVICE, 0, 0, NULL,
				  0, 1000);
	if (size < 0) {
		printk("%s: Unable to send usb control msg: %u\n", __func__, RPU_ENABLE);
		return NULL;
	}

	ret = usb_control_msg(lnx_qspi_priv->usbdev,
				  usb_sndctrlpipe(lnx_qspi_priv->usbdev, 0),
				  IRQ_ENABLE,
				  USB_TYPE_VENDOR | USB_DIR_OUT | USB_RECIP_DEVICE, 0, 0, NULL,
				  0, 1000);
	if (size < 0) {
		printk("%s: Unable to send usb control msg: %u\n", __func__, IRQ_ENABLE);
		return NULL;
	}

	lnx_qspi_priv->dev_added = true;

	return lnx_qspi_priv;
}

static void lnx_shim_bus_usb_dev_rem(void *os_qspi_dev_ctx)
{
	struct qspi_dev *dev = NULL;

	dev = os_qspi_dev_ctx;

	/* Send control msg to remove Wi-Fi device */

	/* TODO: Make qspi_dev a dynamic instance and remove it here */
}

#endif

static void lnx_shim_bus_qspi_dev_host_map_get(void *os_qspi_dev_ctx,
						   struct wifi_nrf_osal_host_map *host_map)
{
	if (!os_qspi_dev_ctx || !host_map) {
		printk("%s: Invalid parameters\n", __func__);
		return;
	}

	host_map->addr = 0;
}

static void irq_work_handler(struct work_struct* work)
{
	struct lnx_shim_intr_priv *intr_priv = NULL;
	int ret = 0;

	intr_priv =
		(struct lnx_shim_intr_priv *)container_of(work, struct lnx_shim_intr_priv, work);

	if(!intr_priv) {
		printk("fail to get back intr priv\n");
	}

	ret = intr_priv->callbk_fn(intr_priv->callbk_data);
	if (ret) {
		printk("%s: Interrupt callback failed\n", __func__);
	}
}

#if defined(CONFIG_NRF700X_ON_QSPI)
static irqreturn_t irq_handler(int irq, void *dev)
{
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = NULL;

	lnx_qspi_priv = dev;

	//printk("IRQ triggered\n");
	// schedule_work(&lnx_qspi_priv->intr_priv.work);
	queue_work(lnx_qspi_priv->wq, &lnx_qspi_priv->intr_priv.work);
	
	return IRQ_HANDLED;
}
#else
static void int_complete(struct urb *urb)
{
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = (struct lnx_shim_bus_qspi_priv *)urb->context;
	int ret;

	if (urb->status != 0 || !urb->actual_length) {
		printk("int urb fail: %d %d\n", ret, urb->actual_length);
		return;
	}

	schedule_work(&lnx_qspi_priv->intr_priv.work);

	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret) {
		printk("Re usb_submit_urb fail: %d\n", ret);
	}
}
#endif

static enum wifi_nrf_status lnx_shim_bus_qspi_intr_reg(void *os_dev_ctx, void *callbk_data,
							   int (*callbk_fn)(void *callbk_data))
{
#if defined(CONFIG_NRF700X_ON_QSPI)
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = NULL;
	int ret;
	int irq_number;

	lnx_qspi_priv = os_dev_ctx;
	if (lnx_qspi_priv->irq_enabled) {
		printk("IRQ registered already\n");
		return WIFI_NRF_STATUS_FAIL;
	}

	irq_number = gpiod_to_irq(lnx_qspi_priv->host_irq);
	
	if (irq_number) {
		ret = request_irq(irq_number, irq_handler, IRQ_TYPE_EDGE_RISING, "NRF7002 IRQ", lnx_qspi_priv);
		if (ret < 0) {
			printk("Cannot request irq\n");
			free_irq(irq_number, NULL);
			lnx_qspi_priv->irq_enabled = false;
			return WIFI_NRF_STATUS_FAIL;
		} else {
			printk("IRQ requested\n");
			lnx_qspi_priv->irq_enabled = true;
		}
	}

	lnx_qspi_priv->intr_priv.callbk_data = callbk_data;
	lnx_qspi_priv->intr_priv.callbk_fn = callbk_fn;
	INIT_WORK(&lnx_qspi_priv->intr_priv.work, irq_work_handler);

	return WIFI_NRF_STATUS_SUCCESS;
#else
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = NULL;
	int ret;

	lnx_qspi_priv = os_dev_ctx;
	lnx_qspi_priv->urb = usb_alloc_urb(0, GFP_KERNEL);

	if (!lnx_qspi_priv->urb)
		return WIFI_NRF_STATUS_FAIL;

	usb_fill_int_urb(lnx_qspi_priv->urb, lnx_qspi_priv->usbdev, usb_rcvintpipe(lnx_qspi_priv->usbdev, 2),
			 lnx_qspi_priv->int_buf, USB_INTR_CONTENT_LENGTH,
			 int_complete, lnx_qspi_priv, 10);
	ret = usb_submit_urb(lnx_qspi_priv->urb, GFP_KERNEL);
	if (ret) {
		printk("usb_submit_urb fail: %d\n", ret);
		goto error;
	}

	lnx_qspi_priv->intr_priv.callbk_data = callbk_data;
	lnx_qspi_priv->intr_priv.callbk_fn = callbk_fn;
	INIT_WORK(&lnx_qspi_priv->intr_priv.work, irq_work_handler);

	return WIFI_NRF_STATUS_SUCCESS;

error:
	usb_free_urb(lnx_qspi_priv->urb);
	return WIFI_NRF_STATUS_FAIL;
#endif
}

static void lnx_shim_bus_qspi_intr_unreg(void *os_qspi_dev_ctx)
{
#if defined(CONFIG_NRF700X_ON_QSPI)
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = NULL;

	lnx_qspi_priv = os_qspi_dev_ctx;
	
	if(lnx_qspi_priv->irq_enabled) {
		free_irq(gpiod_to_irq(lnx_qspi_priv->host_irq), lnx_qspi_priv);
		lnx_qspi_priv->irq_enabled = false;
	}
#else
	struct lnx_shim_bus_qspi_priv *lnx_qspi_priv = NULL;

	lnx_qspi_priv = os_qspi_dev_ctx;
	usb_free_urb(lnx_qspi_priv->urb);
#endif
}

#ifdef CONFIG_NRF_WIFI_LOW_POWER
static void *zep_shim_timer_alloc(void)
{
	struct timer_list *timer = NULL;

	timer = kmalloc(sizeof(*timer), GFP_KERNEL);

	if (!timer)
		LOG_ERR("%s: Unable to allocate memory for work\n", __func__);

	return timer;
}

static void zep_shim_timer_init(void *timer, void (*callback)(unsigned long), unsigned long data)
{
	((struct timer_list *)timer)->function = callback;
	((struct timer_list *)timer)->data = data;

	init_timer(timer);
}

static void zep_shim_timer_free(void *timer)
{
	kfree(timer);
}

static void zep_shim_timer_schedule(void *timer, unsigned long duration)
{
	mod_timer(timer, duration);
}

static void zep_shim_timer_kill(void *timer)
{
	del_timer_sync(timer);
}
#endif /* CONFIG_NRF_WIFI_LOW_POWER */

static const struct wifi_nrf_osal_ops wifi_nrf_os_lnx_ops = {
	.mem_alloc = lnx_shim_mem_alloc,
	.mem_zalloc = lnx_shim_mem_zalloc,
	.mem_free = lnx_shim_mem_free,
	.mem_cpy = memcpy,
	.mem_set = memset,
#if defined(CONFIG_NRF700X_ON_QSPI)
	.qspi_read_reg32 = lnx_shim_qspi_read_reg32,
	.qspi_write_reg32 = lnx_shim_qspi_write_reg32,
	.qspi_cpy_from = lnx_shim_qspi_cpy_from,
	.qspi_cpy_to = lnx_shim_qspi_cpy_to,
#elif defined(CONFIG_NRF700X_ON_USB_ADAPTER)
	.qspi_read_reg32 = lnx_shim_usb_read_reg32,
	.qspi_write_reg32 = lnx_shim_usb_write_reg32,
	.qspi_cpy_from = lnx_shim_usb_cpy_from,
	.qspi_cpy_to = lnx_shim_usb_cpy_to,
#endif
	.spinlock_alloc = lnx_shim_spinlock_alloc,
	.spinlock_free = lnx_shim_spinlock_free,
	.spinlock_init = lnx_shim_spinlock_init,
	.spinlock_take = lnx_shim_spinlock_take,
	.spinlock_rel = lnx_shim_spinlock_rel,

	.spinlock_irq_take = lnx_shim_spinlock_irq_take,
	.spinlock_irq_rel = lnx_shim_spinlock_irq_rel,

	.log_dbg = lnx_shim_pr_dbg,
	.log_info = lnx_shim_pr_info,
	.log_err = lnx_shim_pr_err,

	.llist_node_alloc = lnx_shim_llist_node_alloc,
	.llist_node_free = lnx_shim_llist_node_free,
	.llist_node_data_get = lnx_shim_llist_node_data_get,
	.llist_node_data_set = lnx_shim_llist_node_data_set,
	.llist_alloc = lnx_shim_llist_alloc,
	.llist_free = lnx_shim_llist_free,
	.llist_init = lnx_shim_llist_init,

	.llist_add_node_tail = lnx_shim_llist_add_node_tail,
	.llist_get_node_head = lnx_shim_llist_get_node_head,
	.llist_get_node_nxt = lnx_shim_llist_get_node_nxt,
	.llist_del_node = lnx_shim_llist_del_node,
	.llist_len = lnx_shim_llist_len,

	.nbuf_alloc = lnx_shim_nbuf_alloc,
	.nbuf_free = lnx_shim_nbuf_free,
	.nbuf_headroom_res = lnx_shim_nbuf_headroom_res,
	.nbuf_headroom_get = lnx_shim_nbuf_headroom_get,
	.nbuf_data_size = lnx_shim_nbuf_data_size,
	.nbuf_data_get = lnx_shim_nbuf_data_get,
	.nbuf_data_put = lnx_shim_nbuf_data_put,
	.nbuf_data_push = lnx_shim_nbuf_data_push,
	.nbuf_data_pull = lnx_shim_nbuf_data_pull,

	.tasklet_alloc = lnx_shim_work_alloc,
	.tasklet_free = lnx_shim_work_free,
	.tasklet_init = lnx_shim_work_init,
	.tasklet_schedule = lnx_shim_work_schedule,
	.tasklet_kill = lnx_shim_work_kill,

	.sleep_ms = lnx_shim_msleep,
	.delay_us = lnx_shim_usleep,

	.time_get_curr_us = lnx_shim_time_get_curr_us,
	.time_elapsed_us = lnx_shim_time_elapsed_us,

#if defined(CONFIG_NRF700X_ON_QSPI)
	.bus_qspi_init = lnx_shim_bus_spi_init,
	.bus_qspi_deinit = lnx_shim_bus_spi_deinit,
	.bus_qspi_dev_add = lnx_shim_bus_spi_dev_add,
	.bus_qspi_dev_rem = lnx_shim_bus_spi_dev_rem,
#elif defined(CONFIG_NRF700X_ON_USB_ADAPTER)
	.bus_qspi_init = lnx_shim_bus_usb_init,
	.bus_qspi_deinit = lnx_shim_bus_usb_deinit,
	.bus_qspi_dev_add = lnx_shim_bus_usb_dev_add,
	.bus_qspi_dev_rem = lnx_shim_bus_usb_dev_rem,
#else
#endif
	.bus_qspi_dev_init = lnx_shim_bus_qspi_dev_init,
	.bus_qspi_dev_deinit = lnx_shim_bus_qspi_dev_deinit,
	.bus_qspi_dev_intr_reg = lnx_shim_bus_qspi_intr_reg,
	.bus_qspi_dev_intr_unreg = lnx_shim_bus_qspi_intr_unreg,
	.bus_qspi_dev_host_map_get = lnx_shim_bus_qspi_dev_host_map_get,
#ifdef CONFIG_NRF_WIFI_LOW_POWER
	.timer_alloc = zep_shim_timer_alloc,
	.timer_init = zep_shim_timer_init,
	.timer_free = zep_shim_timer_free,
	.timer_schedule = zep_shim_timer_schedule,
	.timer_kill = zep_shim_timer_kill,

	.bus_qspi_ps_sleep = zep_shim_bus_qspi_ps_sleep,
	.bus_qspi_ps_wake = zep_shim_bus_qspi_ps_wake,
	.bus_qspi_ps_status = zep_shim_bus_qspi_ps_status,
#endif /* CONFIG_NRF_WIFI_LOW_POWER */
};

const struct wifi_nrf_osal_ops *get_os_ops(void)
{
	return &wifi_nrf_os_lnx_ops;
}
