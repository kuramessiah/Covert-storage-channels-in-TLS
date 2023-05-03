/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "suricata-common.h"
#include "threads.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"

#include "flow.h"
#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"
#include "detect-engine-prefilter.h"
#include "detect-tls-session-id.h"

#define DETECT_TLS_SESSION_ID_LEN 1

static int DetectTlsSessionIDSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetSessionIDLength(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);

static int g_tls_session_id_buffer_id = 0;

/**
 * \brief Registration function for keyword: tls.session_id
 */

void DetectTlsSessionIDRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_SESSION_ID].name = "tls.session_id";
    sigmatch_table[DETECT_AL_TLS_SESSION_ID].desc = "buffer to match session id length";
    sigmatch_table[DETECT_AL_TLS_SESSION_ID].url = "/rules/tls-keywords.html#tls-session-id";
    sigmatch_table[DETECT_AL_TLS_SESSION_ID].Setup = DetectTlsSessionIDSetup;
    sigmatch_table[DETECT_AL_TLS_SESSION_ID].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    /* Register engine for Server random */
    DetectAppLayerInspectEngineRegister2("tls.session_id", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetSessionIDLength);
    DetectAppLayerMpmRegister2("tls.session_id", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetSessionIDLength, ALPROTO_TLS, 0);

    /* Register engine for Client random */
    DetectAppLayerInspectEngineRegister2("tls.session_id", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetSessionIDLength);
    DetectAppLayerMpmRegister2("tls.session_id", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetSessionIDLength, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("tls.session_id", "TLS Session ID");

    g_tls_session_id_buffer_id = DetectBufferTypeGetByName("tls.session_id");
}

/**
 * \brief this function setup the tls.random_time sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsSessionIDSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_session_id_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetSessionIDLength(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        
        const SSLState *ssl_state = (SSLState *)f->alstate;

        if (flow_flags & STREAM_TOSERVER) {
            if (!(ssl_state->flags & TLS_TS_RANDOM_SET))
                return NULL;
        } else {
            if (!(ssl_state->flags & TLS_TC_RANDOM_SET))
                return NULL;
        }

        const uint32_t data_len = DETECT_TLS_SESSION_ID_LEN; //MAYBE NEEDED TO INITIAL UPPER
        const uint8_t *data;
        if (flow_flags & STREAM_TOSERVER) {
            data = ssl_state->server_connp.random + 32;
        } else {
            data = ssl_state->client_connp.random + 32;
        }
        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}
