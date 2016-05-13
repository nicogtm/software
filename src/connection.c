#include "osd-private.h"
#include <libglip.h>

#include <stdio.h>

OSD_EXPORT
int osd_connect(struct osd_context *ctx) {
    pthread_mutex_init(&ctx->reg_access.lock, 0);
    pthread_cond_init(&ctx->reg_access.cond_complete, 0);

    pthread_mutex_init(&ctx->mem_access.lock, 0);
    pthread_cond_init(&ctx->mem_access.cond_complete, 0);

    int rv = ctx->functions.connect(ctx);

    if (rv != 0) {
        return rv;
    }

    rv = osd_system_enumerate(ctx);
    if (rv != OSD_SUCCESS) {
        return rv;
    }

    control_init(ctx);

    return OSD_SUCCESS;
}

OSD_EXPORT
int osd_send_packet(struct osd_context *ctx, uint16_t *packet) {
    return ctx->functions.send(ctx, packet);
}

OSD_EXPORT
void osd_print_packet(uint16_t *packet) {
    for (uint16_t i = 0; i < packet[0]+1; i++) {
        printf("  %04x\n", packet[i]);
    }
}

void osd_handle_packet(struct osd_context *ctx, uint16_t *packet) {
    uint8_t type = (packet[2] >> 10);
    uint16_t size = packet[0];

    if ((type >> 4) == 0) {
        // Register access
        pthread_mutex_lock(&ctx->reg_access.lock);

        memcpy(&ctx->reg_access.resp_packet, packet, (size+1)*2);

        ctx->reg_access.size = size;

        pthread_cond_signal(&ctx->reg_access.cond_complete);

        pthread_mutex_unlock(&ctx->reg_access.lock);
    } else {
        uint16_t mod_id = osd_addr2modid(ctx, packet[2] & 0x3ff);

        size_t ev_size = (type & 0xf);

        if (size != ev_size + 2) {
            //fprintf(stderr, "Incorrect event size packet received\n");
            //return;
            ev_size = size - 2;
        }

        if ((type >> 4) == OSD_EVENT_PACKET) {
            void *parg = ctx->module_handlers[mod_id]->packet_handler.arg;
            if (!ctx->module_handlers[mod_id]->packet_handler.call) {
                fprintf(stderr, "No module handler for module %d\n", mod_id);
                return;
            }
            ctx->module_handlers[mod_id]->packet_handler.call(ctx, parg, packet);
        } else if ((type >> 4) == OSD_EVENT_TRACE) {
            void *parg = ctx->module_handlers[mod_id]->packet_handler.arg;
            if (!ctx->module_handlers[mod_id]->packet_handler.call) {
                fprintf(stderr, "No module handler for module %d\n", mod_id);
                return;
            }
            ctx->module_handlers[mod_id]->packet_handler.call(ctx, parg, packet);
        }
    }
}
