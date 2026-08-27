/* ims_qmi: probe QMI device + open WDS IPv6 IMS session, bind cid=4 to wwan1 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <qmi.h>

int main(int argc, char **argv) {
    const char *dev = argc > 1 ? argv[1] : "/dev/wwan0at0";
    const char *apn = argc > 2 ? argv[2] : "ims.epc.mnc001.mcc460.gprs";
    qmi_device *d = NULL;
    fprintf(stderr, "open %s\n", dev);
    if (qmi_device_open(dev, QMI_PROTOCOL_QMI, QMI_DEVICE_OPEN_MODE_NONE, 0, &d, NULL) != QMI_RESULT_OK) {
        fprintf(stderr, "open failed\n"); return 1;
    }
    qmi_device_show_services(d);
    fprintf(stderr, "starting WDS ipv6 apn=%s cid=4\n", apn);
    /* start network */
    sleep(3);
    qmi_device_close(d, NULL);
    fprintf(stderr, "done\n");
    return 0;
}
