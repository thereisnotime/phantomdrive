#include "phantomdrive.h"
#include "crypto.h"
#include "bot_state.h"
#include "emmc_ops.h"
#include "CH56x_ecdc.h"
#include "CH56x_debug_log.h"
#include "CH56x_usb20_devbulk.h"
#include <stdbool.h>
#include <string.h>

volatile uint8_t phantomdrive_state = STATE_LOCKED;
static bool phantomdrive_unlock_pending = false;

__attribute__((aligned(16))) uint32_t aes_key[8] __attribute__((section(".DMADATA")));
static __attribute__((aligned(16))) uint8_t meta_buf[SECTOR_SIZE] __attribute__((section(".DMADATA")));

static uint8_t pending_pw[128];
static size_t pending_pw_len;
static bool pw_partial;

/* Physical sector reserved for HMAC enrollment: last sector of the locked
 * region.  Layout: bytes 0-3 magic "OVRD", bytes 4-35 HMAC-SHA256 verifier. */
#define META_MAGIC_0 'O'
#define META_MAGIC_1 'V'
#define META_MAGIC_2 'R'
#define META_MAGIC_3 'D'

static bool meta_sector_read(void)
{
	uint8_t s;

	PFIC_DisableIRQ(EMMC_IRQn);
	R16_EMMC_INT_FG = 0xffff;
	TF_EMMCParam.EMMCOpErr = 0;

	R32_EMMC_DMA_BEG1 = (uint32_t)meta_buf;
	R32_EMMC_TRAN_MODE = EMMC_TRAN_AUTOGAPSTOP;
	R32_EMMC_BLOCK_CFG = ((uint32_t)SECTOR_SIZE << 16) | 1;
	EMMCSendCmd(LOCKED_SECTORS - 1,
	            RB_EMMC_CKIDX | RB_EMMC_CKCRC | RESP_TYPE_48 | EMMC_CMD18);

	do { s = CheckCMDComp(&TF_EMMCParam); } while (s == CMD_NULL);
	if (s == CMD_FAILED) goto fail;

	while (!(R16_EMMC_INT_FG & (RB_EMMC_IF_TRANDONE | RB_EMMC_IF_BKGAP))) {
		if (TF_EMMCParam.EMMCOpErr) goto fail;
	}
	R16_EMMC_INT_FG = 0xffff;

	R32_EMMC_TRAN_MODE = 0;
	EMMCSendCmd(0, RB_EMMC_CKIDX | RB_EMMC_CKCRC | RESP_TYPE_R1b | EMMC_CMD12);
	do { s = CheckCMDComp(&TF_EMMCParam); } while (s == CMD_NULL);

	TF_EMMCParam.EMMCOpErr = 0;
	PFIC_EnableIRQ(EMMC_IRQn);
	return true;
fail:
	R16_EMMC_INT_FG = 0xffff;
	TF_EMMCParam.EMMCOpErr = 0;
	PFIC_EnableIRQ(EMMC_IRQn);
	return false;
}

static bool meta_sector_write(void)
{
	uint16_t reqnum = 1;
	uint8_t status;

	PFIC_DisableIRQ(EMMC_IRQn);
	R16_EMMC_INT_FG = 0xffff;
	TF_EMMCParam.EMMCOpErr = 0;
	TF_EMMCParam.EMMCSecSize = SECTOR_SIZE;

	status = EMMCCardWriteMulSec(&TF_EMMCParam, &reqnum, meta_buf, LOCKED_SECTORS - 1);

	R16_EMMC_INT_FG = 0xffff;
	TF_EMMCParam.EMMCOpErr = 0;
	PFIC_EnableIRQ(EMMC_IRQn);
	return (status == CMD_SUCCESS);
}

void phantomdrive_init(void)
{
	R16_ECEC_CTRL = 0;
	R8_ECDC_INT_FG = 0xFF;

	g_bot.capacity = LOCKED_SECTORS;
	phantomdrive_state = STATE_LOCKED;
	log_printf("phantomdrive: locked, %lu sectors\r\n", LOCKED_SECTORS);
}

static void phantomdrive_unlock(void)
{
	log_printf("phantomdrive: deriving key (%u bytes)...\r\n", (unsigned)pending_pw_len);

	static const uint8_t hmac_msg[] = "phantomdrive-v1";
	uint8_t key_bytes[32];
	uint8_t computed_mac[32];

	derive_key(pending_pw, pending_pw_len, key_bytes);
	memset(pending_pw, 0, sizeof(pending_pw));
	pending_pw_len = 0;

	hmac_sha256(key_bytes, 32, hmac_msg, sizeof(hmac_msg) - 1, computed_mac);

	if (meta_sector_read()) {
		bool enrolled = (meta_buf[0] == META_MAGIC_0 && meta_buf[1] == META_MAGIC_1 &&
		                 meta_buf[2] == META_MAGIC_2 && meta_buf[3] == META_MAGIC_3);
		if (enrolled) {
			if (memcmp(meta_buf + 4, computed_mac, 32) != 0) {
				log_printf("phantomdrive: HMAC mismatch - wrong key or tampered disk\r\n");
				memset(key_bytes, 0, sizeof(key_bytes));
				memset(computed_mac, 0, sizeof(computed_mac));
				return;
			}
			log_printf("phantomdrive: HMAC verified\r\n");
		} else {
			memset(meta_buf, 0, SECTOR_SIZE);
			meta_buf[0] = META_MAGIC_0; meta_buf[1] = META_MAGIC_1;
			meta_buf[2] = META_MAGIC_2; meta_buf[3] = META_MAGIC_3;
			memcpy(meta_buf + 4, computed_mac, 32);
			meta_sector_write();
			log_printf("phantomdrive: HMAC enrolled\r\n");
		}
	} else {
		log_printf("phantomdrive: meta sector read failed, skipping HMAC check\r\n");
	}

	memset(computed_mac, 0, sizeof(computed_mac));
	memcpy(aes_key, key_bytes, 32);
	memset(key_bytes, 0, sizeof(key_bytes));

	uint32_t initial_ctr[4] = {0, 0, 0, 0};
	ECDC_Init(MODE_AES_CTR, ECDCCLK_240MHZ, KEYLENGTH_256BIT,
	          (puint32_t)aes_key, (puint32_t)initial_ctr);

	g_bot.capacity = TF_EMMCParam.EMMCSecNum - LOCKED_SECTORS;
	phantomdrive_state = STATE_UNLOCKED;

	log_printf("phantomdrive: unlocked, %lu sectors\r\n", g_bot.capacity);

	g_bot.transfer_flags = 0;
	g_bot.read_pending = false;
	g_bot.write_pending = false;
	USB20_Device_Init(DISABLE);
	PFIC_EnableIRQ(USBHS_IRQn);
	USB20_Device_Init(ENABLE);

	log_printf("phantomdrive: re-enumerated\r\n");
}

void phantomdrive_snoop_write(uint8_t *buf, uint32_t len)
{
	if (phantomdrive_state != STATE_LOCKED || phantomdrive_unlock_pending)
		return;

	/* Continue appending password from previous buffer */
	if (pw_partial) {
		size_t end = 0;
		while (end < len && pending_pw_len < sizeof(pending_pw) &&
		       buf[end] != '\n' && buf[end] != '\r' && buf[end] != '\0')
			pending_pw[pending_pw_len++] = buf[end++];

		memset(buf, 0, end);

		if (end < len || pending_pw_len >= sizeof(pending_pw)) {
			pw_partial = false;
			if (pending_pw_len > 0) {
				phantomdrive_unlock_pending = true;
				log_printf("phantomdrive: password snooped (%u bytes)\r\n",
				           (unsigned)pending_pw_len);
			}
		}
		return;
	}

	const char *prefix = "password:";
	const size_t prefix_len = 9;
	uint32_t i;

	for (i = 0; i + prefix_len <= len; i++) {
		if (buf[i] != 'p')
			continue;
		if (memcmp(buf + i, prefix, prefix_len) != 0)
			continue;

		size_t pw_start = i + prefix_len;
		size_t pw_end = pw_start;
		while (pw_end < len && (pw_end - pw_start) < sizeof(pending_pw) &&
		       buf[pw_end] != '\n' && buf[pw_end] != '\r' && buf[pw_end] != '\0')
			pw_end++;

		size_t pw_len = pw_end - pw_start;
		memcpy(pending_pw, buf + pw_start, pw_len);
		pending_pw_len = pw_len;
		memset(buf + i, 0, pw_end - i);

		if (pw_end < len || pw_len >= sizeof(pending_pw)) {
			if (pw_len > 0) {
				phantomdrive_unlock_pending = true;
				log_printf("phantomdrive: password snooped (%u bytes)\r\n",
				           (unsigned)pw_len);
			}
		} else {
			pw_partial = true;
		}
		return;
	}
}

void phantomdrive_poll(void)
{
	if (!phantomdrive_unlock_pending)
		return;
	phantomdrive_unlock_pending = false;
	phantomdrive_unlock();
}

void phantomdrive_ecdc_set_sector_nonce(uint32_t sd_lba)
{
	uint32_t ctr[4];
	ctr[0] = 0;
	ctr[1] = sd_lba;
	ctr[2] = 0;
	ctr[3] = 0;
	ECDC_SetCount((puint32_t)ctr);
}

void phantomdrive_ecdc_disable_data_path(void)
{
	R16_ECEC_CTRL &= ~(RB_ECDC_WRSRAM_EN | RB_ECDC_WRPERI_EN |
	                    RB_ECDC_RDPERI_EN | RB_ECDC_MODE_SEL);
}

/* ECDC SRAM_LEN is in 128-bit (16-byte) units [CH569DS1 Ch15] */
void phantomdrive_crypt_buf(uint8_t *buf, uint32_t sd_lba, uint16_t num_sectors)
{
	static uint8_t clog = 0;
	uint32_t pre = *(volatile uint32_t*)buf;

	uint16_t i;
	for (i = 0; i < num_sectors; i++) {
		phantomdrive_ecdc_set_sector_nonce(sd_lba + i);
		ECDC_Excute(SELFDMA_ENCRY, MODE_LITTLE_ENDIAN);
		ECDC_SelfDMA((uint32_t)(buf + i * SECTOR_SIZE), SECTOR_SIZE / 16);
	}
	/* Disable ECDC so subsequent eMMC DMA isn't double-encrypted */
	phantomdrive_ecdc_disable_data_path();

#ifdef DEBUG_USB
	if (clog < 5) {
		uint32_t post = *(volatile uint32_t*)buf;
		log_printf("C lba=%lu n=%u %08lx->%08lx ctrl=%04x\r\n",
		           sd_lba, num_sectors, pre, post, R16_ECEC_CTRL);
		clog++;
	}
#endif
}
