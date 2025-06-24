#include "bp.h"
#include "daemon.h"

int bp_send_to_eid(char *payload, int payload_size, char *eid, int eid_size)
{
    Sdr sdr;
    Object bundlePayload;
    Object bundleZco;

    sdr = bp_get_sdr();
    if (sdr == NULL)
    {
        puts("*** Failed to get sdr.");
        return 0;
    }
    oK(sdr_begin_xn(sdr));
    bundlePayload = sdr_string_create(sdr, payload);
    if (bundlePayload == 0)
    {
        sdr_end_xn(sdr);
        putErrmsg("No text object.", NULL);
        return 0;
    }

    bundleZco = zco_create(sdr, ZcoSdrSource, bundlePayload, 0,
                           payload_size, ZcoOutbound);
    if (bundleZco == 0 || bundleZco == (Object)ERROR)
    {
        sdr_end_xn(sdr);
        putErrmsg("No text object.", NULL);
        return 0;
    }

    if (bp_send(NULL, eid, NULL, 86400, BP_STD_PRIORITY, 0, 0, 0, NULL,
                bundleZco, NULL) <= 0)
    {
        sdr_end_xn(sdr);
        putErrmsg("No text object.", NULL);
        putErrmsg("bpsockets daemon can't send bundle.", NULL);
        return 0;
    }

    sdr_end_xn(sdr);
    return 1;
}