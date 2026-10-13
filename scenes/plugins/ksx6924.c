/*
 * Parser for KS X 6924 (전국호환교통카드) cards
 *
 * Reads Korean contactless pre-paid / post-pay transit cards: T-money,
 * Cashbee (eB), Rail+, Mybi and other cards built on KS X 6924.
 *
 * Read flow (no command here changes card state):
 *  1. SELECT the CONFIG DF and parse its FCI / EF_CONFIG record 1
 *     (국토교통부 「교통카드 관련 장비의 전국호환성 인증 요령」 별표 1,
 *     8.2-8.3 and 2부 6.6 "Application 정보 조회 프로토콜").
 *  2. SELECT the transit ADF named by tag 4F (or a well-known AID when the
 *     card has no CONFIG DF) and pick up EF_PURSE_INFO (FCI tag B0).
 *  3. Send the balance command advertised in tag 11, falling back to the
 *     common 90 4C 00 00 04.
 *  4. READ BINARY / READ RECORD the additional info files listed in tag
 *     9F10 (별표 1 8.5) and the transaction log in SFI 4.
 *
 * Initialize Card (90 02) is deliberately never sent: per KS X 6924-2 6.1
 * the card increments its transaction counter NT_EP on it.
 *
 * EF_PURSE_INFO and the SFI 4 transaction record layouts are not part of
 * KS X 6924; they follow Metrodroid's KSX6924PurseInfo / TMoneyTrip, with
 * USERCODE and DISRATE at offsets 25 and 26 (Metrodroid reads 26 and 27,
 * which overlaps BALMAX at 27-30 in its own T-money test dump).
 *
 * Originally a T-Money balance reader by Justus Perlwitz.
 *
 * References:
 *  - KS X 6924-1:2014, KS X 6924-2:2014
 *  - https://github.com/metrodroid/metrodroid/tree/master/src/commonMain/kotlin/au/id/micolous/metrodroid/card/ksx6924
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dolphin/dolphin.h>
#include <lib/nfc/protocols/iso14443_4a/iso14443_4a_poller.h>

#include "../../metroflip_i.h"
#include "../../metroflip_plugins.h"
#include "../../api/metroflip/metroflip_api.h"

#define TAG "Metroflip:Scene:KSX6924"

#define KSX6924_SW_OK 0x9000

#define KSX6924_AID_MAX_LEN       16
#define KSX6924_PURSE_INFO_LEN    47
#define KSX6924_MAX_AUX_FILES     4
#define KSX6924_MAX_AUX_RECORDS   5
#define KSX6924_AUX_DATA_LEN      64
#define KSX6924_MAX_TRIPS         10
#define KSX6924_TRIP_RECORD_LEN   46
#define KSX6924_TRIP_MIN_LEN      33
#define KSX6924_TRANSACTION_SFI   4
#define KSX6924_EF_CONFIG_SFI     1
#define KSX6924_APDU_MAX_LEN      (5 + KSX6924_AID_MAX_LEN + 1)
#define KSX6924_RESPONSE_MAX_LEN  256

/* 부가 정보 파일 File Type (별표 1 8.3.2) */
#define KSX6924_FILE_TRANSPARENT 0x1
#define KSX6924_FILE_CYCLIC      0x7

/* 카드 규격 및 선후불 구분, top nibble (별표 1 8.3.2) */
#define KSX6924_SPEC_POSTPAY 0x1

typedef struct {
    uint8_t type;
    uint8_t sfi;
    uint16_t max_len;
    uint8_t record_count;
    uint8_t record_len[KSX6924_MAX_AUX_RECORDS];
    uint8_t record[KSX6924_MAX_AUX_RECORDS][KSX6924_AUX_DATA_LEN];
} Ksx6924AuxFile;

typedef struct {
    /* CONFIG DF / EF_CONFIG */
    bool has_config;
    bool has_spec;
    uint8_t spec[2];
    bool has_support;
    uint16_t support;
    bool has_idcenter;
    uint8_t idcenter;
    bool has_balance_cmd;
    uint8_t balance_cmd[5];
    uint8_t adf_aid[KSX6924_AID_MAX_LEN];
    uint8_t adf_aid_len;
    bool has_holder;
    uint8_t holder;
    bool has_expiry;
    uint8_t expiry[2];
    uint8_t serial[8];
    uint8_t serial_len;
    uint8_t mgmt[8];
    uint8_t mgmt_len;
    uint8_t aux_count;
    Ksx6924AuxFile aux[KSX6924_MAX_AUX_FILES];

    /* Transit ADF */
    uint8_t purse[KSX6924_PURSE_INFO_LEN];
    uint8_t purse_len;
    bool has_balance;
    uint32_t balance;
    uint8_t trip_count;
    uint8_t trip_len[KSX6924_MAX_TRIPS];
    uint8_t trip[KSX6924_MAX_TRIPS][KSX6924_TRIP_RECORD_LEN];
} Ksx6924Card;

typedef struct {
    Iso14443_4aPoller* poller;
    BitBuffer* tx;
    BitBuffer* rx;
    bool transport_error;
} Ksx6924Io;

typedef struct {
    uint8_t code;
    const char* name;
} Ksx6924Name;

/* CONFIG DF AID: 인증대행기관 관리, as used by every certified card */
static const uint8_t ksx6924_config_df_aid[] = {0xA0, 0x00, 0x00, 0x04, 0x52, 0x00, 0x01};

/* Transit ADFs tried when a card has no CONFIG DF (Metrodroid APP_NAME) */
static const uint8_t ksx6924_known_aids[][7] = {
    {0xD4, 0x10, 0x00, 0x00, 0x03, 0x00, 0x01}, /* T-money, Snapper */
    {0xD4, 0x10, 0x00, 0x00, 0x14, 0x00, 0x01}, /* Cashbee / eB */
    {0xD4, 0x10, 0x00, 0x00, 0x30, 0x00, 0x01}, /* MOIBA */
    {0xD4, 0x10, 0x65, 0x09, 0x90, 0x00, 0x20}, /* K-Cash */
};

/* Common balance command (Metrodroid INS_GET_BALANCE) */
static const uint8_t ksx6924_default_balance_cmd[] = {0x90, 0x4C, 0x00, 0x00, 0x04};

/* IDCENTER (별표 1 8.3.2) */
static const Ksx6924Name ksx6924_issuers[] = {
    {0x01, "KFTC"},
    {0x02, "A-Cash"},
    {0x03, "Mybi"},
    {0x05, "V-Cash"},
    {0x06, "Mondex Korea"},
    {0x07, "Korea Expressway"},
    {0x08, "Korea Smart Card"},
    {0x09, "Korail Networks"},
    {0x0B, "eB Card"},
    {0x0C, "Seoul Bus Assoc."},
    {0x0D, "Cardnet"},
};

/* Card title per IDCENTER */
static const Ksx6924Name ksx6924_brands[] = {
    {0x01, "K-Cash"},
    {0x03, "Mybi"},
    {0x08, "T-money"},
    {0x09, "Rail+"},
    {0x0B, "Cashbee"},
};

/* 소지자 정보 (별표 1 8.3.2); 0F and FF from TTAK.KO-12.0240 via Metrodroid */
static const Ksx6924Name ksx6924_holders[] = {
    {0x01, "General"},
    {0x02, "Child"},
    {0x03, "Youth"},
    {0x04, "Senior"},
    {0x05, "Disabled"},
    {0x0F, "Test"},
    {0x11, "Bus"},
    {0x12, "Truck"},
    {0xFF, "Inactive"},
};

/* ALG_EP (KS X 6924-1 7.9) */
static const Ksx6924Name ksx6924_algorithms[] = {
    {0x00, "SEED"},
    {0x10, "T-DES"},
};

/* EF_PURSE_INFO CARDTYPE (Metrodroid) */
static const Ksx6924Name ksx6924_purse_types[] = {
    {0x00, "Prepaid"},
    {0x10, "Postpaid"},
    {0x15, "Mobile postpaid"},
};

/* EF_PURSE_INFO DISRATE (Metrodroid TMoneyPurseInfoResolver) */
static const Ksx6924Name ksx6924_discounts[] = {
    {0x00, "None"},
    {0x10, "Disabled"},
    {0x11, "Disabled companion"},
    {0x20, "Veteran"},
    {0x21, "Veteran companion"},
};

/* EF_PURSE_INFO TCODE (Metrodroid TMoneyPurseInfoResolver) */
static const Ksx6924Name ksx6924_carriers[] = {
    {0x00, "None"},
    {0x01, "SK Telecom"},
    {0x02, "KT"},
    {0x03, "LG U+"},
};

/* EF_PURSE_INFO CCODE (Metrodroid TMoneyPurseInfoResolver) */
static const Ksx6924Name ksx6924_card_companies[] = {
    {0x00, "None"},
    {0x01, "KB Kookmin"},
    {0x02, "NongHyup"},
    {0x03, "Lotte"},
    {0x04, "BC"},
    {0x05, "Samsung"},
    {0x06, "Shinhan"},
    {0x07, "Citi"},
    {0x08, "KEB"},
    {0x09, "Woori"},
    {0x0A, "Hana SK"},
    {0x0B, "Hyundai"},
};

/* Read by the poller thread, displayed by the main thread on
   MetroflipCustomEventPollerSuccess. Allocated in on_enter. */
static Ksx6924Card* ksx6924_card = NULL;

static void delay(int milliseconds) {
    furi_thread_flags_wait(0, FuriFlagWaitAny, milliseconds);
}

static const char*
    ksx6924_lookup(const Ksx6924Name* names, size_t count, uint8_t code, const char* fallback) {
    for(size_t i = 0; i < count; i++) {
        if(names[i].code == code) return names[i].name;
    }
    return fallback;
}

static void ksx6924_lookup_or_hex(
    char* out,
    size_t out_size,
    const Ksx6924Name* names,
    size_t count,
    uint8_t code) {
    const char* name = ksx6924_lookup(names, count, code, NULL);
    if(name) {
        snprintf(out, out_size, "%s", name);
    } else {
        snprintf(out, out_size, "Unknown (0x%02X)", code);
    }
}

static uint32_t ksx6924_be32(const uint8_t* data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) |
           data[3];
}

static bool ksx6924_is_bcd(const uint8_t* data, size_t len) {
    for(size_t i = 0; i < len; i++) {
        if((data[i] >> 4) > 9 || (data[i] & 0x0F) > 9) return false;
    }
    return true;
}

static uint8_t ksx6924_bcd(uint8_t value) {
    return (value >> 4) * 10 + (value & 0x0F);
}

static void ksx6924_hex(
    char* out,
    size_t out_size,
    const uint8_t* data,
    size_t len,
    uint8_t group) {
    size_t pos = 0;
    out[0] = '\0';
    for(size_t i = 0; i < len && pos + 3 <= out_size; i++) {
        if(group && i && (i % group) == 0) {
            if(pos + 4 > out_size) break;
            out[pos++] = ' ';
        }
        snprintf(out + pos, out_size - pos, "%02X", data[i]);
        pos += 2;
    }
}

/* 12345 -> "12,345", -500 -> "-500" */
static void ksx6924_format_amount(char* out, size_t out_size, int64_t value) {
    char digits[16];
    /* Card amounts are 32-bit (KS X 6924-1 7.4, 7.11) */
    uint32_t magnitude = value < 0 ? (uint32_t)(-value) : (uint32_t)value;
    snprintf(digits, sizeof(digits), "%lu", (unsigned long)magnitude);

    size_t len = strlen(digits);
    size_t pos = 0;
    if(value < 0 && pos + 1 < out_size) out[pos++] = '-';
    for(size_t i = 0; i < len && pos + 1 < out_size; i++) {
        if(i && ((len - i) % 3) == 0) {
            if(pos + 2 >= out_size) break;
            out[pos++] = ',';
        }
        out[pos++] = digits[i];
    }
    out[pos] = '\0';
}

/* BCD YYYYMMDD -> "YYYY-MM-DD" */
static void ksx6924_format_date(char* out, size_t out_size, const uint8_t* data) {
    if(!ksx6924_is_bcd(data, 4)) {
        snprintf(out, out_size, "-");
        return;
    }
    snprintf(
        out,
        out_size,
        "%02u%02u-%02u-%02u",
        ksx6924_bcd(data[0]),
        ksx6924_bcd(data[1]),
        ksx6924_bcd(data[2]),
        ksx6924_bcd(data[3]));
}

/* ---- APDU exchange ---- */

static uint16_t ksx6924_exchange(Ksx6924Io* io, const uint8_t* apdu, size_t apdu_len) {
    bit_buffer_reset(io->tx);
    bit_buffer_reset(io->rx);
    bit_buffer_append_bytes(io->tx, apdu, apdu_len);

    Iso14443_4aError error = iso14443_4a_poller_send_block(io->poller, io->tx, io->rx);
    if(error != Iso14443_4aErrorNone) {
        FURI_LOG_E(TAG, "iso14443_4a_poller_send_block error %d", error);
        io->transport_error = true;
        return 0;
    }

    size_t len = bit_buffer_get_size_bytes(io->rx);
    if(len < 2) {
        FURI_LOG_E(TAG, "Response too short: %zu bytes", len);
        return 0;
    }
    return (bit_buffer_get_byte(io->rx, len - 2) << 8) | bit_buffer_get_byte(io->rx, len - 1);
}

/* Sends one APDU whose last byte is Le and returns its status word.
   Follows 6Cxx (wrong Le) and 61xx (GET RESPONSE, KS X 6924-2 5.1.1.7).
   Response data without the SW is copied to out (truncated to out_size). */
static uint16_t ksx6924_transceive(
    Ksx6924Io* io,
    const uint8_t* apdu,
    size_t apdu_len,
    uint8_t* out,
    size_t out_size,
    size_t* out_len) {
    uint8_t cmd[KSX6924_APDU_MAX_LEN];
    furi_check(apdu_len <= sizeof(cmd));
    memcpy(cmd, apdu, apdu_len);
    if(out_len) *out_len = 0;

    uint16_t sw = ksx6924_exchange(io, cmd, apdu_len);
    if(io->transport_error) return 0;

    if((sw >> 8) == 0x6C) {
        cmd[apdu_len - 1] = sw & 0xFF;
        sw = ksx6924_exchange(io, cmd, apdu_len);
        if(io->transport_error) return 0;
    }
    if((sw >> 8) == 0x61) {
        const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, sw & 0xFF};
        sw = ksx6924_exchange(io, get_response, sizeof(get_response));
        if(io->transport_error) return 0;
    }

    if(out && out_len && sw != 0) {
        size_t data_len = bit_buffer_get_size_bytes(io->rx) - 2;
        size_t copy_len = MIN(data_len, out_size);
        for(size_t i = 0; i < copy_len; i++) {
            out[i] = bit_buffer_get_byte(io->rx, i);
        }
        *out_len = copy_len;
    }
    return sw;
}

static uint16_t ksx6924_select(
    Ksx6924Io* io,
    const uint8_t* aid,
    size_t aid_len,
    uint8_t* out,
    size_t out_size,
    size_t* out_len) {
    /* SELECT by DF name (KS X 6924-2 5.1.1.1), Le = 00 */
    uint8_t cmd[KSX6924_APDU_MAX_LEN];
    cmd[0] = 0x00;
    cmd[1] = 0xA4;
    cmd[2] = 0x04;
    cmd[3] = 0x00;
    cmd[4] = aid_len;
    memcpy(cmd + 5, aid, aid_len);
    cmd[5 + aid_len] = 0x00;
    return ksx6924_transceive(io, cmd, aid_len + 6, out, out_size, out_len);
}

static uint16_t ksx6924_read_record(
    Ksx6924Io* io,
    uint8_t sfi,
    uint8_t record,
    uint8_t* out,
    size_t out_size,
    size_t* out_len) {
    /* READ RECORD (KS X 6924-2 5.1.1.5): P2 b8-b4 = SFI, b3-b1 = 100 */
    const uint8_t cmd[] = {0x00, 0xB2, record, (sfi << 3) | 0x04, 0x00};
    return ksx6924_transceive(io, cmd, sizeof(cmd), out, out_size, out_len);
}

static uint16_t ksx6924_read_binary(
    Ksx6924Io* io,
    uint8_t sfi,
    uint8_t le,
    uint8_t* out,
    size_t out_size,
    size_t* out_len) {
    /* READ BINARY (KS X 6924-2 5.1.1.3): P1 b8 = 1 selects by SFI, offset 0 */
    const uint8_t cmd[] = {0x00, 0xB0, 0x80 | sfi, 0x00, le};
    return ksx6924_transceive(io, cmd, sizeof(cmd), out, out_size, out_len);
}

/* ---- BER-TLV ---- */

typedef void (*Ksx6924TlvCallback)(uint32_t tag, const uint8_t* value, size_t len, void* context);

/* 6F FCI Template, A5 FCI Proprietary Template, 87 Config Data Template.
   B0 and BF0C are left alone: their constructed bit is set but their
   content is issuer-defined. */
static bool ksx6924_tlv_is_template(uint32_t tag) {
    return tag == 0x6F || tag == 0xA5 || tag == 0x87;
}

static void ksx6924_tlv_walk(
    const uint8_t* data,
    size_t len,
    Ksx6924TlvCallback callback,
    void* context,
    uint8_t depth) {
    size_t pos = 0;
    while(pos < len) {
        uint8_t first = data[pos++];
        if(first == 0x00 || first == 0xFF) continue; /* padding */

        uint32_t tag = first;
        if((first & 0x1F) == 0x1F) {
            uint8_t next;
            do {
                if(pos >= len) return;
                next = data[pos++];
                tag = (tag << 8) | next;
            } while((next & 0x80) && tag <= 0xFFFF);
        }

        if(pos >= len) return;
        size_t value_len = data[pos++];
        if(value_len & 0x80) {
            uint8_t length_bytes = value_len & 0x7F;
            if(length_bytes == 0 || length_bytes > 2 || length_bytes > len - pos) return;
            value_len = 0;
            while(length_bytes--) {
                value_len = (value_len << 8) | data[pos++];
            }
        }
        if(value_len > len - pos) return;

        if(ksx6924_tlv_is_template(tag) && depth < 4) {
            ksx6924_tlv_walk(data + pos, value_len, callback, context, depth + 1);
        } else {
            callback(tag, data + pos, value_len, context);
        }
        pos += value_len;
    }
}

/* EF_CONFIG record 1 / CONFIG DF FCI (별표 1 8.2-8.3) */
static void ksx6924_config_tag(uint32_t tag, const uint8_t* value, size_t len, void* context) {
    Ksx6924Card* card = context;

    switch(tag) {
    case 0x50:
        if(len >= 2) {
            memcpy(card->spec, value, 2);
            card->has_spec = true;
        }
        break;
    case 0x47:
        if(len >= 2) {
            card->support = (value[0] << 8) | value[1];
            card->has_support = true;
        }
        break;
    case 0x43:
        if(len >= 1) {
            card->idcenter = value[0];
            card->has_idcenter = true;
        }
        break;
    case 0x11:
        if(len == sizeof(card->balance_cmd)) {
            memcpy(card->balance_cmd, value, len);
            card->has_balance_cmd = true;
        }
        break;
    case 0x4F:
        if(len >= 5 && len <= KSX6924_AID_MAX_LEN) {
            memcpy(card->adf_aid, value, len);
            card->adf_aid_len = len;
        }
        break;
    case 0x9F10:
        /* File Type(3bit) || SFI(5bit) || Max Length(2byte), repeated */
        for(size_t i = 0; i + 3 <= len && card->aux_count < KSX6924_MAX_AUX_FILES; i += 3) {
            Ksx6924AuxFile* file = &card->aux[card->aux_count++];
            file->type = value[i] >> 5;
            file->sfi = value[i] & 0x1F;
            file->max_len = (value[i + 1] << 8) | value[i + 2];
        }
        break;
    case 0x45:
        if(len >= 1) {
            card->holder = value[0];
            card->has_holder = true;
        }
        break;
    case 0x5F24:
        if(len >= 2) {
            memcpy(card->expiry, value, 2);
            card->has_expiry = true;
        }
        break;
    case 0x12:
        card->serial_len = MIN(len, sizeof(card->serial));
        memcpy(card->serial, value, card->serial_len);
        break;
    case 0x13:
        card->mgmt_len = MIN(len, sizeof(card->mgmt));
        memcpy(card->mgmt, value, card->mgmt_len);
        break;
    default:
        break;
    }
}

static void ksx6924_adf_tag(uint32_t tag, const uint8_t* value, size_t len, void* context) {
    Ksx6924Card* card = context;
    if(tag == 0xB0) {
        card->purse_len = MIN(len, sizeof(card->purse));
        memcpy(card->purse, value, card->purse_len);
    }
}

/* ---- Card helpers ---- */

static bool ksx6924_card_idcenter(const Ksx6924Card* card, uint8_t* idcenter) {
    if(card->has_idcenter) {
        *idcenter = card->idcenter;
        return true;
    }
    if(card->purse_len >= 4) {
        *idcenter = card->purse[3];
        return true;
    }
    return false;
}

static bool ksx6924_card_is_postpay(const Ksx6924Card* card) {
    if(card->has_spec) return (card->spec[0] >> 4) == KSX6924_SPEC_POSTPAY;
    if(card->purse_len >= 1) return card->purse[0] == 0x10 || card->purse[0] == 0x15;
    return false;
}

/* Snapper (Wellington) reuses the T-money applet; its SFI 4 records have
   bytes 26-45 set to FF (Metrodroid SnapperTransitData.check). */
static bool ksx6924_card_is_snapper(const Ksx6924Card* card) {
    if(card->trip_count == 0) return false;
    for(uint8_t i = 0; i < card->trip_count; i++) {
        if(card->trip_len[i] != KSX6924_TRIP_RECORD_LEN) return false;
        for(uint8_t j = 26; j < KSX6924_TRIP_RECORD_LEN; j++) {
            if(card->trip[i][j] != 0xFF) return false;
        }
    }
    return true;
}

static void ksx6924_format_balance(
    const Ksx6924Card* card,
    char* out,
    size_t out_size,
    int64_t value) {
    char amount[20];
    if(ksx6924_card_is_snapper(card)) {
        bool negative = value < 0;
        uint64_t magnitude = negative ? (uint64_t)(-value) : (uint64_t)value;
        ksx6924_format_amount(amount, sizeof(amount), (int64_t)(magnitude / 100));
        snprintf(
            out,
            out_size,
            "%sNZ$%s.%02u",
            negative ? "-" : "",
            amount,
            (unsigned)(magnitude % 100));
    } else {
        ksx6924_format_amount(amount, sizeof(amount), value);
        snprintf(out, out_size, "%s KRW", amount);
    }
}

/* ---- Reader ---- */

/* Returns false only when the card went away mid-read. */
static bool ksx6924_read_card(Ksx6924Io* io, Ksx6924Card* card, bool* found) {
    uint8_t* response = malloc(KSX6924_RESPONSE_MAX_LEN);
    size_t response_len = 0;
    uint16_t sw;
    *found = false;

    do {
        /* 1. CONFIG DF (2부 6.6 Application 정보 조회 프로토콜) */
        sw = ksx6924_select(
            io,
            ksx6924_config_df_aid,
            sizeof(ksx6924_config_df_aid),
            response,
            KSX6924_RESPONSE_MAX_LEN,
            &response_len);
        if(io->transport_error) break;
        if(sw == KSX6924_SW_OK) {
            card->has_config = true;
            ksx6924_tlv_walk(response, response_len, ksx6924_config_tag, card, 0);

            /* Config not carried in the FCI: read EF_CONFIG record 1 */
            if(card->adf_aid_len == 0) {
                sw = ksx6924_read_record(
                    io,
                    KSX6924_EF_CONFIG_SFI,
                    1,
                    response,
                    KSX6924_RESPONSE_MAX_LEN,
                    &response_len);
                if(io->transport_error) break;
                if(sw == KSX6924_SW_OK) {
                    ksx6924_tlv_walk(response, response_len, ksx6924_config_tag, card, 0);
                }
            }
        } else {
            FURI_LOG_I(TAG, "No CONFIG DF (SW %04X)", sw);
        }

        /* 2. Transit ADF */
        bool adf_selected = false;
        if(card->adf_aid_len) {
            sw = ksx6924_select(
                io,
                card->adf_aid,
                card->adf_aid_len,
                response,
                KSX6924_RESPONSE_MAX_LEN,
                &response_len);
            if(io->transport_error) break;
            adf_selected = sw == KSX6924_SW_OK;
        }
        for(size_t i = 0; !adf_selected && i < COUNT_OF(ksx6924_known_aids); i++) {
            sw = ksx6924_select(
                io,
                ksx6924_known_aids[i],
                sizeof(ksx6924_known_aids[i]),
                response,
                KSX6924_RESPONSE_MAX_LEN,
                &response_len);
            if(io->transport_error) break;
            if(sw == KSX6924_SW_OK) {
                adf_selected = true;
                memcpy(card->adf_aid, ksx6924_known_aids[i], sizeof(ksx6924_known_aids[i]));
                card->adf_aid_len = sizeof(ksx6924_known_aids[i]);
            }
        }
        if(io->transport_error) break;
        if(!adf_selected) {
            FURI_LOG_W(TAG, "No KS X 6924 application found");
            break;
        }
        *found = true;
        ksx6924_tlv_walk(response, response_len, ksx6924_adf_tag, card, 0);

        /* 3. Balance */
        const uint8_t* balance_cmd = card->has_balance_cmd ? card->balance_cmd :
                                                             ksx6924_default_balance_cmd;
        sw = ksx6924_transceive(io, balance_cmd, 5, response, 4, &response_len);
        if(io->transport_error) break;
        if(sw == KSX6924_SW_OK && response_len >= 1 && response_len <= 4) {
            card->balance = 0;
            for(size_t i = 0; i < response_len; i++) {
                card->balance = (card->balance << 8) | response[i];
            }
            card->has_balance = true;
        } else {
            FURI_LOG_W(TAG, "Balance command failed (SW %04X)", sw);
        }

        /* 4. Additional info files (별표 1 8.5) */
        for(uint8_t i = 0; i < card->aux_count && !io->transport_error; i++) {
            Ksx6924AuxFile* file = &card->aux[i];
            if(file->type == KSX6924_FILE_TRANSPARENT) {
                uint8_t le = (file->max_len == 0 || file->max_len > KSX6924_AUX_DATA_LEN) ?
                                 KSX6924_AUX_DATA_LEN :
                                 file->max_len;
                size_t len = 0;
                sw = ksx6924_read_binary(
                    io, file->sfi, le, file->record[0], KSX6924_AUX_DATA_LEN, &len);
                if(sw == KSX6924_SW_OK) {
                    file->record_len[0] = len;
                    file->record_count = 1;
                }
            } else if(file->type == KSX6924_FILE_CYCLIC) {
                for(uint8_t r = 0; r < KSX6924_MAX_AUX_RECORDS; r++) {
                    size_t len = 0;
                    sw = ksx6924_read_record(
                        io, file->sfi, r + 1, file->record[r], KSX6924_AUX_DATA_LEN, &len);
                    if(io->transport_error || sw != KSX6924_SW_OK) break;
                    file->record_len[r] = len;
                    file->record_count = r + 1;
                }
            }
        }
        if(io->transport_error) break;

        /* 5. Transaction log (SFI 4, newest first) */
        for(uint8_t r = 0; r < KSX6924_MAX_TRIPS; r++) {
            size_t len = 0;
            sw = ksx6924_read_record(
                io,
                KSX6924_TRANSACTION_SFI,
                r + 1,
                card->trip[card->trip_count],
                KSX6924_TRIP_RECORD_LEN,
                &len);
            if(io->transport_error || sw != KSX6924_SW_OK) break;
            if(len >= KSX6924_TRIP_MIN_LEN) {
                card->trip_len[card->trip_count++] = len;
            }
        }
    } while(false);

    free(response);
    return !io->transport_error;
}

static NfcCommand ksx6924_poller_callback(NfcGenericEvent event, void* context) {
    furi_assert(event.protocol == NfcProtocolIso14443_4a);
    Metroflip* app = context;

    const Iso14443_4aPollerEvent* iso14443_4a_event = event.event_data;
    if(iso14443_4a_event->type != Iso14443_4aPollerEventTypeReady) {
        return NfcCommandContinue;
    }

    NotificationApp* notification = furi_record_open(RECORD_NOTIFICATION);
    notification_message(notification, &sequence_set_vibro_on);
    delay(50);
    notification_message(notification, &sequence_reset_vibro);
    furi_record_close(RECORD_NOTIFICATION);

    nfc_device_set_data(app->nfc_device, NfcProtocolIso14443_4a, nfc_poller_get_data(app->poller));

    Ksx6924Io io = {
        .poller = event.instance,
        .tx = bit_buffer_alloc(Metroflip_POLLER_MAX_BUFFER_SIZE),
        .rx = bit_buffer_alloc(Metroflip_POLLER_MAX_BUFFER_SIZE),
        .transport_error = false,
    };

    memset(ksx6924_card, 0, sizeof(Ksx6924Card));
    bool found = false;
    if(!ksx6924_read_card(&io, ksx6924_card, &found)) {
        view_dispatcher_send_custom_event(app->view_dispatcher, MetroflipCustomEventPollerFail);
    } else if(!found) {
        view_dispatcher_send_custom_event(app->view_dispatcher, MetroflipCustomEventWrongCard);
    } else {
        FURI_LOG_I(TAG, "Card read successfully");
        /* Display happens on the main thread (PollerSuccess handler) - never
           build UI or switch views from the NFC worker thread. */
        view_dispatcher_send_custom_event(app->view_dispatcher, MetroflipCustomEventPollerSuccess);
    }

    bit_buffer_free(io.tx);
    bit_buffer_free(io.rx);
    return NfcCommandStop;
}

/* ---- Card view ---- */

static void ksx6924_add_card_page(View* view, const Ksx6924Card* card) {
    char val[METROFLIP_CARD_VIEW_VALUE_LEN];
    uint8_t p = metroflip_card_view_add_page(view, "Card Info");
    bool postpay = ksx6924_card_is_postpay(card);

    if(card->has_balance) {
        ksx6924_format_balance(card, val, sizeof(val), card->balance);
    } else {
        snprintf(val, sizeof(val), "Unavailable");
    }
    /* BAL_EP is the accumulated amount on post-pay cards (KS X 6924-1 7.11) */
    metroflip_card_view_add_field(view, p, postpay ? "Total Used" : "Balance", val, true);

    if(card->serial_len) {
        ksx6924_hex(val, sizeof(val), card->serial, card->serial_len, 2);
        metroflip_card_view_add_field(view, p, "Card No", val, false);
    } else if(card->purse_len >= 12) {
        ksx6924_hex(val, sizeof(val), card->purse + 4, 8, 2);
        metroflip_card_view_add_field(view, p, "Card No", val, false);
    }

    uint8_t idcenter;
    if(ksx6924_card_idcenter(card, &idcenter)) {
        ksx6924_lookup_or_hex(
            val, sizeof(val), ksx6924_issuers, COUNT_OF(ksx6924_issuers), idcenter);
        metroflip_card_view_add_field(view, p, "Issuer", val, false);
    }

    if(card->has_spec || card->purse_len >= 1) {
        metroflip_card_view_add_field(view, p, "Type", postpay ? "Postpaid" : "Prepaid", false);
    }

    if(card->has_holder || card->purse_len >= 26) {
        uint8_t holder = card->has_holder ? card->holder : card->purse[25];
        ksx6924_lookup_or_hex(
            val, sizeof(val), ksx6924_holders, COUNT_OF(ksx6924_holders), holder);
        metroflip_card_view_add_field(view, p, "Holder", val, false);
    }

    if(card->has_expiry && ksx6924_is_bcd(card->expiry, 2)) {
        /* 유효기간 'YYMM' */
        snprintf(
            val,
            sizeof(val),
            "20%02u-%02u",
            ksx6924_bcd(card->expiry[0]),
            ksx6924_bcd(card->expiry[1]));
        metroflip_card_view_add_field(view, p, "Expires", val, false);
    } else if(card->purse_len >= 25) {
        ksx6924_format_date(val, sizeof(val), card->purse + 21);
        metroflip_card_view_add_field(view, p, "Expires", val, false);
    }

    if(card->mgmt_len &&
       (card->mgmt_len != card->serial_len || memcmp(card->mgmt, card->serial, card->mgmt_len))) {
        ksx6924_hex(val, sizeof(val), card->mgmt, card->mgmt_len, 2);
        metroflip_card_view_add_field(view, p, "Mgmt No", val, false);
    }
}

static void ksx6924_add_config_page(View* view, const Ksx6924Card* card) {
    char val[METROFLIP_CARD_VIEW_VALUE_LEN];
    uint8_t p = metroflip_card_view_add_page(view, "Config DF");

    if(!card->has_config) {
        metroflip_card_view_add_field(view, p, "Config DF", "Not present", false);
    }

    if(card->has_spec) {
        /* top nibble: pre/post-pay, then major.minor (별표 1 8.3.2) */
        snprintf(
            val,
            sizeof(val),
            "%u.%u %s",
            card->spec[0] & 0x0F,
            card->spec[1],
            (card->spec[0] >> 4) == KSX6924_SPEC_POSTPAY ? "Postpaid" : "Prepaid");
        metroflip_card_view_add_field(view, p, "Spec", val, false);
    }

    if(card->has_support) {
        snprintf(
            val,
            sizeof(val),
            "%04X%s%s%s%s",
            card->support,
            (card->support & 0x01) ? " 14443-3" : "",
            (card->support & 0x02) ? " -4" : "",
            (card->support & 0x04) ? " CFG" : "",
            (card->support & 0x08) ? " HiPass" : "");
        metroflip_card_view_add_field(view, p, "Supports", val, false);
    }

    if(card->has_idcenter) {
        snprintf(val, sizeof(val), "0x%02X", card->idcenter);
        metroflip_card_view_add_field(view, p, "IDCENTER", val, false);
    }

    ksx6924_hex(val, sizeof(val), card->adf_aid, card->adf_aid_len, 0);
    metroflip_card_view_add_field(view, p, "ADF AID", val, false);

    if(card->has_balance_cmd) {
        ksx6924_hex(val, sizeof(val), card->balance_cmd, sizeof(card->balance_cmd), 0);
        metroflip_card_view_add_field(view, p, "Balance APDU", val, false);
    }

    if(card->has_config) {
        snprintf(val, sizeof(val), "%u", card->aux_count);
        metroflip_card_view_add_field(view, p, "Aux Files", val, false);
    }
}

static void ksx6924_add_purse_page(View* view, const Ksx6924Card* card) {
    char val[METROFLIP_CARD_VIEW_VALUE_LEN];
    const uint8_t* d = card->purse;
    uint8_t p = metroflip_card_view_add_page(view, "Purse Info");

    ksx6924_lookup_or_hex(
        val, sizeof(val), ksx6924_purse_types, COUNT_OF(ksx6924_purse_types), d[0]);
    metroflip_card_view_add_field(view, p, "Card Type", val, false);

    ksx6924_lookup_or_hex(
        val, sizeof(val), ksx6924_algorithms, COUNT_OF(ksx6924_algorithms), d[1]);
    metroflip_card_view_add_field(view, p, "Algorithm", val, false);

    snprintf(val, sizeof(val), "0x%02X", d[2]);
    metroflip_card_view_add_field(view, p, "Key Version", val, false);

    ksx6924_lookup_or_hex(val, sizeof(val), ksx6924_issuers, COUNT_OF(ksx6924_issuers), d[3]);
    metroflip_card_view_add_field(view, p, "Issuer", val, false);

    ksx6924_hex(val, sizeof(val), d + 4, 8, 2);
    metroflip_card_view_add_field(view, p, "CSN", val, false);

    ksx6924_hex(val, sizeof(val), d + 12, 5, 0);
    metroflip_card_view_add_field(view, p, "Auth ID", val, false);

    ksx6924_format_date(val, sizeof(val), d + 17);
    metroflip_card_view_add_field(view, p, "Issued", val, false);

    ksx6924_format_date(val, sizeof(val), d + 21);
    metroflip_card_view_add_field(view, p, "Expires", val, false);

    if(card->purse_len < KSX6924_PURSE_INFO_LEN) return;

    ksx6924_lookup_or_hex(val, sizeof(val), ksx6924_holders, COUNT_OF(ksx6924_holders), d[25]);
    metroflip_card_view_add_field(view, p, "User Code", val, false);

    ksx6924_lookup_or_hex(
        val, sizeof(val), ksx6924_discounts, COUNT_OF(ksx6924_discounts), d[26]);
    metroflip_card_view_add_field(view, p, "Discount", val, false);

    ksx6924_format_balance(card, val, sizeof(val), ksx6924_be32(d + 27));
    metroflip_card_view_add_field(view, p, "Max Balance", val, false);

    ksx6924_hex(val, sizeof(val), d + 31, 2, 0);
    metroflip_card_view_add_field(view, p, "Branch", val, false);

    ksx6924_format_balance(card, val, sizeof(val), ksx6924_be32(d + 33));
    metroflip_card_view_add_field(view, p, "Tx Limit", val, false);

    ksx6924_lookup_or_hex(val, sizeof(val), ksx6924_carriers, COUNT_OF(ksx6924_carriers), d[37]);
    metroflip_card_view_add_field(view, p, "Carrier", val, false);

    ksx6924_lookup_or_hex(
        val, sizeof(val), ksx6924_card_companies, COUNT_OF(ksx6924_card_companies), d[38]);
    metroflip_card_view_add_field(view, p, "Card Company", val, false);
}

static void ksx6924_add_history_page(View* view, const Ksx6924Card* card) {
    /* Sized for the worst case snprintf can see; real values fit the card
       view, which truncates to its own field lengths. */
    char label[24];
    char val[56];
    char amount[20];
    char balance[20];
    uint8_t p = UINT8_MAX;

    for(uint8_t i = 0; i < card->trip_count; i++) {
        /* 1B type, 1B ?, 4B balance after, 4B counter, 4B amount, ...,
           7B BCD YYYYMMDDhhmmss at offset 26 (Metrodroid TMoneyTrip) */
        const uint8_t* d = card->trip[i];
        uint8_t type = d[0];
        uint32_t cost = ksx6924_be32(d + 10);
        const uint8_t* time = d + 26;

        bool time_valid = ksx6924_is_bcd(time, 7);
        if(cost == 0 && !time_valid) continue;

        if(p == UINT8_MAX) p = metroflip_card_view_add_page(view, "History");

        if(time_valid) {
            snprintf(
                label,
                sizeof(label),
                "%02u%02u-%02u-%02u %02u:%02u",
                ksx6924_bcd(time[0]),
                ksx6924_bcd(time[1]),
                ksx6924_bcd(time[2]),
                ksx6924_bcd(time[3]),
                ksx6924_bcd(time[4]),
                ksx6924_bcd(time[5]));
        } else {
            snprintf(label, sizeof(label), "#%u (no date)", i + 1);
        }

        ksx6924_format_amount(amount, sizeof(amount), cost);
        ksx6924_format_amount(balance, sizeof(balance), ksx6924_be32(d + 2));
        if(type == 0x01) {
            snprintf(val, sizeof(val), "Pay %s, bal %s", amount, balance);
        } else if(type == 0x02) {
            snprintf(val, sizeof(val), "Top-up %s, bal %s", amount, balance);
        } else {
            snprintf(val, sizeof(val), "%02X: %s, bal %s", type, amount, balance);
        }
        metroflip_card_view_add_field(view, p, label, val, false);
    }
}

static void ksx6924_add_aux_page(View* view, const Ksx6924Card* card) {
    char label[METROFLIP_CARD_VIEW_LABEL_LEN];
    char val[METROFLIP_CARD_VIEW_VALUE_LEN];
    uint8_t p = metroflip_card_view_add_page(view, "Aux Files");

    for(uint8_t i = 0; i < card->aux_count; i++) {
        const Ksx6924AuxFile* file = &card->aux[i];
        const char* kind = file->type == KSX6924_FILE_TRANSPARENT ? "Binary" :
                           file->type == KSX6924_FILE_CYCLIC      ? "Cyclic" :
                                                                    "RFU";
        snprintf(label, sizeof(label), "SFI %u", file->sfi);
        snprintf(
            val, sizeof(val), "%s, max %u, %u read", kind, file->max_len, file->record_count);
        metroflip_card_view_add_field(view, p, label, val, false);

        /* Data is issuer-defined (8.5.3); show the leading bytes */
        for(uint8_t r = 0; r < file->record_count; r++) {
            snprintf(label, sizeof(label), " #%u (%uB)", r + 1, file->record_len[r]);
            ksx6924_hex(val, sizeof(val), file->record[r], file->record_len[r], 0);
            metroflip_card_view_add_field(view, p, label, val, false);
        }
    }
}

static void ksx6924_show_card_view(Metroflip* app) {
    const Ksx6924Card* card = ksx6924_card;
    View* view = metroflip_card_view_alloc(app);

    const char* title = "KS X 6924";
    uint8_t idcenter;
    if(ksx6924_card_is_snapper(card)) {
        title = "Snapper";
    } else if(ksx6924_card_idcenter(card, &idcenter)) {
        title = ksx6924_lookup(ksx6924_brands, COUNT_OF(ksx6924_brands), idcenter, title);
    }
    metroflip_card_view_set_title(view, title);

    ksx6924_add_card_page(view, card);
    ksx6924_add_config_page(view, card);
    if(card->purse_len >= 25) ksx6924_add_purse_page(view, card);
    /* Snapper keeps its timestamps in SFI 3, which is not parsed here */
    if(!ksx6924_card_is_snapper(card)) ksx6924_add_history_page(view, card);
    if(card->aux_count) ksx6924_add_aux_page(view, card);

    /* No save: the card is read over live ISO 7816 commands, there is no
       re-parseable card image to store. */
    metroflip_card_view_show(app);
}

/* ---- Plugin ---- */

static void ksx6924_on_enter(Metroflip* app) {
    dolphin_deed(DolphinDeedNfcRead);

    if(app->data_loaded) {
        /* Read over live ISO 7816 commands only - there is no saved-file
           parse path (and the load scene never routes here). */
        View* view = metroflip_card_view_alloc(app);
        metroflip_card_view_set_title(view, "KS X 6924");
        uint8_t p = metroflip_card_view_add_page(view, "");
        metroflip_card_view_add_field(view, p, "Status", "Saved files not supported", false);
        metroflip_card_view_show(app);
        return;
    }

    ksx6924_card = malloc(sizeof(Ksx6924Card));

    Popup* popup = app->popup;
    popup_set_icon(popup, 0, 3, &I_RFIDDolphinReceive_97x61);
    popup_set_header(popup, "Apply\n card to\nthe back", 68, 30, AlignLeft, AlignTop);
    view_dispatcher_switch_to_view(app->view_dispatcher, MetroflipViewPopup);

    app->poller = nfc_poller_alloc(app->nfc, NfcProtocolIso14443_4a);
    nfc_poller_start(app->poller, ksx6924_poller_callback, app);

    metroflip_app_blink_start(app);
}

static bool ksx6924_on_event(Metroflip* app, SceneManagerEvent event) {
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == MetroflipCustomEventPollerSuccess) {
            /* Release the NFC hardware before showing results (the worker
               returned NfcCommandStop; stop+free is still our job). */
            if(app->poller) {
                nfc_poller_stop(app->poller);
                nfc_poller_free(app->poller);
                app->poller = NULL;
            }
            metroflip_app_blink_stop(app);
            ksx6924_show_card_view(app);
            consumed = true;
        } else if(event.event == MetroflipCustomEventPollerFail) {
            Popup* popup = app->popup;
            popup_set_header(popup, "Error, try\n again", 68, 30, AlignLeft, AlignTop);
            consumed = true;
        }
    } else if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(app->scene_manager, MetroflipSceneStart);
        consumed = true;
    }

    return consumed;
}

static void ksx6924_on_exit(Metroflip* app) {
    popup_reset(app->popup);
    metroflip_app_blink_stop(app);

    if(app->poller && !app->data_loaded) {
        nfc_poller_stop(app->poller);
        nfc_poller_free(app->poller);
        app->poller = NULL;
    }

    free(ksx6924_card);
    ksx6924_card = NULL;
}

static const MetroflipPlugin ksx6924_plugin = {
    .card_name = "KS X 6924",
    .plugin_on_enter = ksx6924_on_enter,
    .plugin_on_event = ksx6924_on_event,
    .plugin_on_exit = ksx6924_on_exit,
};

/* Plugin descriptor to comply with basic plugin specification */
static const FlipperAppPluginDescriptor ksx6924_plugin_descriptor = {
    .appid = METROFLIP_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = METROFLIP_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &ksx6924_plugin,
};

const FlipperAppPluginDescriptor* ksx6924_plugin_ep(void) {
    return &ksx6924_plugin_descriptor;
}
