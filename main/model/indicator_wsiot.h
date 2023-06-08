#ifndef INDICATOR_WIFI_H
#define INDICATOR_WIFI_H

#include "config.h"
#include "view_data.h"

#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "mqtt_client.h"
#include "wsiotsdk.h"

#include "ProtoBuf/user_data.pb.h"

#ifdef __cplusplus
extern "C" {
#endif

int indicator_wsiot_init(void);

#ifdef __cplusplus
}
#endif

#endif
