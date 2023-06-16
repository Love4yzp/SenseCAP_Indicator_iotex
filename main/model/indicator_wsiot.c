#include "indicator_wsiot.h"
#include "esp_sntp.h"
#include "freertos/semphr.h"
#include "nvs.h"

#include "iotex_config.h"
#include "mqtt_client.h"

#include "wsiotsdk.h"
#include "ProtoBuf/user_data.pb.h"

#define wsiot_CFG_STORAGE "wsiot-cfg"

static const char *TAG = "wsiot";
static bool net_flag = false;


#define KEY_BITS 256 // It defines the size of the key in bits (256).
#define IOTEX_DEBUG_ENABLE
#define IOTEX_DEBUG_ENABLE_EXT

/*These macros define the source of the signing key (none, static data, flash, or PRNG)*/
#define IOTEX_SIGNKEY_USE_NONE 0x00
#define IOTEX_SIGNKEY_USE_STATIC_DATA 0x01
#define IOTEX_SIGNKEY_USE_FLASH 0x02 // Not Support
#define IOTEX_SIGNKEY_USE_PRNG 0x04

#define IOTEX_SIGNKEY_USE_MODE IOTEX_SIGNKEY_USE_PRNG // It sets the signing key usage mode to PRNG.

#define IOTEX_SIGNKEY_ECC_MODE PSA_ECC_FAMILY_SECP_K1 // It sets the elliptic curve cryptography (ECC) mode to SECP_K1. 椭圆曲线密码

#if (IOTEX_SIGNKEY_USE_MODE == IOTEX_SIGNKEY_USE_STATIC_DATA)
static const uint8_t private_key[] = {0xa1, 0x73, 0x6f, 0xbf, 0x37, 0xa2, 0xfc, 0xb8, 0xfe, 0xe2, 0x02, 0xdb, 0x0c, 0x63, 0x91, 0xdf, 0xa4, 0x61, 0x86, 0x29, 0xb1, 0x86, 0xa6, 0x90, 0x65, 0x85, 0x2d, 0xfc, 0xd8, 0x8f, 0x58, 0x19};
#endif

#if (IOTEX_SIGNKEY_USE_MODE == IOTEX_SIGNKEY_USE_PRNG)
#define IOTEX_SEED_USER_DEFINE 69834
#endif

void time_sync_notification_cb(struct timeval *tv) //  Callback function to handle time synchronization events.
{
    ESP_LOGI(TAG, "Notification of a time synchronization event");
}

static void obtain_time(void) //  Function to obtain the current time using SNTP (Simple Network Time Protocol).
{
    /**
     * NTP server address could be aquired via DHCP,
     * see following menuconfig options:
     * 'LWIP_DHCP_GET_NTP_SRV' - enable STNP over DHCP
     * 'LWIP_SNTP_DEBUG' - enable debugging messages
     *
     * NOTE: This call should be made BEFORE esp aquires IP address from DHCP,
     * otherwise NTP option would be rejected by default.
     */
#if LWIP_DHCP_GET_NTP_SRV
    sntp_servermode_dhcp(1); // accept NTP offers from DHCP server, if any
#endif

    // initialize_sntp();

    // wait for time to be set
    time_t now = 0;
    struct tm timeinfo = {0};
    int retry = 0;
    const int retry_count = 15;
    while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET && ++retry < retry_count)
    {
        ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry, retry_count);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
    time(&now);
    localtime_r(&now, &timeinfo);
}

time_t iotex_time_set_func(void) //  Function to set the IoT device's time using the system clock.
{
    return time(NULL);
}

psa_key_id_t key_id = 0; // This variable represents the ID of the key used for cryptographic operations. It is initially set to 0.

esp_mqtt_client_handle_t mqtt_client = NULL;

uint8_t exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(KEY_BITS)]; // This array is used to store the exported public key in ECC format.
uint32_t exported_len; // This variable holds the length of the exported public key.

static void log_error_if_nonzero(const char *message, int error_code) // This function logs an error message if the given error code is non-zero. It helps in handling and reporting errors.
{
    if (error_code != 0)
    {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
}

int iotex_mqtt_pubscription(unsigned char *topic, unsigned char *buf, unsigned int buflen, int qos)
{
    return esp_mqtt_client_publish(mqtt_client, (const char *)topic, (const char *)buf, buflen, 1, 0);
}

int iotex_mqtt_subscription(unsigned char *topic)
{
    return esp_mqtt_client_subscribe(mqtt_client, (const char *)topic, 1);
}

// This conditional compilation block includes code for signing messages if the IOTEX_USE_SIGN_FUNC_EXT macro is defined.
#if IOTEX_USE_SIGN_FUNC_EXT
int iotex_sign_message_func(const uint8_t *input, size_t input_length, uint8_t *signature, size_t *signature_length) //  Function to sign a message using the private key.
{
    return psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), input, input_length, signature, 64, signature_length);
}
#endif

// This function generates an ECC key pair and exports the public key. It sets key attributes, generates the key pair, and exports the public key.
void iotex_generate_signkey(unsigned char *exported_key, unsigned int *key_len) //  Function to generate an ECC key pair and export the public key.
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    uint8_t exported[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(KEY_BITS)];
    size_t exported_length = 0;

    printf("Generate a key pair...\n");

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(IOTEX_SIGNKEY_ECC_MODE));
    psa_set_key_bits(&attributes, KEY_BITS);

    status = psa_generate_key(&attributes, &key_id);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to generate key %d\n", status);
        return;
    }

#ifdef IOTEX_DEBUG_ENABLE
    printf("Success to generate a key pair: key id : %x\n", key_id);
#endif

    status = psa_export_key(key_id, exported_key, 32, &exported_length);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to export pair key %d\n", status);
        return;
    }

#ifdef IOTEX_DEBUG_ENABLE
    printf("Exported a pair key len %d\n", exported_length);
#endif

    *key_len = exported_length;

#ifdef IOTEX_DEBUG_ENABLE
    for (int i = 0; i < exported_length; i++)
    {
        printf("%02x ", exported_key[i]);
    }
    printf("\n");
#endif

    status = psa_export_public_key(key_id, exported, sizeof(exported), &exported_length);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to export public key %d\n", status);
        return;
    }
#ifdef IOTEX_DEBUG_ENABLE
    printf("Exported a public key len %d\n", exported_length);

    for (int i = 0; i < exported_length; i++)
    {
        printf("%02x ", exported[i]);
    }
    printf("\n");
#endif
}

//This function imports a private key, configures key attributes, and sets the imported key ID. It also exports the public key and performs some debug-related operations.
void iotex_import_key_example(void) //  Function to import a private key and configure key attributes.
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    unsigned char prikey[32] = {0};
    char dev_address[100] = {0};

    uint8_t key_mode = 0;

#if (IOTEX_SIGNKEY_USE_MODE == IOTEX_SIGNKEY_USE_STATIC_DATA)

    memcpy(prikey, private_key, sizeof(prikey));
    key_mode = 1;

#endif

#if (IOTEX_SIGNKEY_USE_MODE == IOTEX_SIGNKEY_USE_PRNG)

    unsigned int prikey_len = 0;

    extern void default_SetSeed(unsigned int seed);
    default_SetSeed(IOTEX_SEED_USER_DEFINE);
    iotex_generate_signkey(prikey, &prikey_len);

    key_mode = 0;
#endif

    if (key_mode)
    {

        /* Set key attributes */
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(IOTEX_SIGNKEY_ECC_MODE));
        psa_set_key_bits(&attributes, 256);

        /* Import the key */
        status = psa_import_key(&attributes, prikey, 32, &key_id);
        if (status != PSA_SUCCESS)
        {
#ifdef IOTEX_DEBUG_ENABLE
            printf("Failed to import pri key err %d\n", status);
#endif
            key_id = 0;

            return;
        }
#ifdef IOTEX_DEBUG_ENABLE
        else
            printf("Success to import pri key keyid %x\n", key_id);
#endif
    }

    status = psa_export_public_key(key_id, exported, sizeof(exported), (size_t *)&exported_len);
    if (status != PSA_SUCCESS)
    {
#ifdef IOTEX_DEBUG_ENABLE
        printf("Failed to export public key %d\n", status);
#endif
        return;
    }

#ifdef IOTEX_DEBUG_ENABLE
    printf("Exported a public key len %d\n", exported_len);
    for (int i = 0; i < exported_len; i++)
    {
        printf("%02x ", exported[i]);
    }
    printf("\n");
#endif

    iotex_dev_access_generate_dev_addr((const unsigned char *)exported, dev_address);
    printf("Dev_addr : %s\n", dev_address);

#ifdef IOTEX_DEBUG_ENABLE_EXT
    unsigned char inbuf[] = "hello devnet";
    unsigned char buf[65] = {0};
    unsigned int sinlen = 0;

    status = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), inbuf, strlen((const char *)inbuf), (unsigned char *)buf, 65, &sinlen);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to sign message %d\n", status);
    }
    else
    {
        printf("Success to sign message %d\n", sinlen);
    }

#ifdef IOTEX_DEBUG_ENABLE
    printf("Exported a sign len %d\n", sinlen);
    for (int i = 0; i < sinlen; i++)
    {
        printf("%02x ", buf[i]);
    }
    printf("\n");
#endif

    status = psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), inbuf, strlen((const char *)inbuf), (unsigned char *)buf, sinlen);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to verify message %d\n", status);
    }
    else
    {
        printf("Success to verify message\n");
    }
#endif
}
typedef struct __packed user_data
{
    int i;
    float f;
    bool b;
} user_data_t;

void iotex_devnet_upload_data_example_raw(void) // Uploads raw user data to the IoT device.
{

    user_data_t user_data;
    unsigned int len = sizeof(user_data);

    user_data.i = 64;
    user_data.f = 128.128;
    user_data.b = true;

    iotex_dev_access_data_upload_with_userdata((void *)&user_data, len, IOTEX_USER_DATA_TYPE_RAW);
}

void iotex_devnet_upload_data_example_json(void) // Uploads user data in JSON format to the IoT device.
{

    cJSON *user_data = cJSON_CreateObject();

    cJSON_AddNumberToObject(user_data, "sensor_1", 10);
    cJSON_AddNumberToObject(user_data, "sensor_2", 5.5);
    cJSON_AddBoolToObject(user_data, "sensor_3", true);

    iotex_dev_access_data_upload_with_userdata(user_data, 1, IOTEX_USER_DATA_TYPE_JSON);
}

void iotex_devnet_upload_data_example_pb(void) // Uploads user data in Protocol Buffers (PB) format to the IoT device.
{

    unsigned char sensor_buf[user_data_size] = {0};
    pb_ostream_t ostream_sensor = {0};
    user_data sensor = user_data_init_zero;

    sensor.sensor_1 = 32;
    sensor.sensor_2 = 64.128;
    sensor.sensor_3 = true;

    ostream_sensor = pb_ostream_from_buffer(sensor_buf, user_data_size);
    if (!pb_encode(&ostream_sensor, user_data_fields, &sensor))
    {
        printf("pb encode [event] error in [%s]\n", PB_GET_ERROR(&ostream_sensor));
        return;
    }

    iotex_dev_access_data_upload_with_userdata(sensor_buf, ostream_sensor.bytes_written, IOTEX_USER_DATA_TYPE_PB);
}

extern void default_SetSeed(unsigned int seed);

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%d", base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
#if 0
        msg_id = esp_mqtt_client_subscribe(client, "/topic/qos0", 0);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

        msg_id = esp_mqtt_client_subscribe(client, "/topic/qos1", 1);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

        msg_id = esp_mqtt_client_unsubscribe(client, "/topic/qos1");
        ESP_LOGI(TAG, "sent unsubscribe successful, msg_id=%d", msg_id);
#endif
        // Subscribe MQTT topic
        msg_id = esp_mqtt_client_subscribe(client, IOTEX_MQTT_SUB_TOPIC_DEFAULT, 0);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

        iotex_dev_access_set_mqtt_status(IOTEX_MQTT_CONNECTED);

        //  restore switch state for UI and HA.
        // struct view_data_ha_switch_data switch_data;
        // for(int i ; i < CONFIG_HA_SWITCH_ENTITY_NUM; i++ ) {
        //     switch_data.index = i;
        //     switch_data.value = switch_state[i];
        //     esp_event_post_to(view_event_handle, VIEW_EVENT_BASE, VIEW_EVENT_HA_SWITCH_SET,  &switch_data, sizeof(switch_data), portMAX_DELAY);
        // }

        // esp_event_post_to(view_event_handle, VIEW_EVENT_BASE, VIEW_EVENT_HA_MQTT_CONNECTED, NULL, 0, portMAX_DELAY);

        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        iotex_dev_access_set_mqtt_status(IOTEX_MQTT_DISCONNECTED);
        break;

    case MQTT_EVENT_SUBSCRIBED:

        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
#if 0
        msg_id = esp_mqtt_client_publish(client, "/topic/qos0", "data", 0, 0, 0);
        ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
#endif
        iotex_dev_access_set_mqtt_status(IOTEX_MQTT_SUB_COMPLATED);

        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
        printf("DATA=%.*s\r\n", event->data_len, event->data);

        //        iotex_dev_access_mqtt_input((uint8_t *)event->topic, (uint8_t *)event->data, (uint32_t)event->data_len);

        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT)
        {
            log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            log_error_if_nonzero("captured as transport's socket errno", event->error_handle->esp_transport_sock_errno);
            ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
        }
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}

static void mqtt_app_start(void)
{
    static bool init_flag = false;
    if (init_flag)
    {
        return;
    }
    init_flag = true;
    const esp_mqtt_client_config_t mqtt_cfg = {

#if 0
		.broker.address.uri = "mqtts://a11homvea4zo8t-ats.iot.us-east-1.amazonaws.com:8883",
		.broker.verification.certificate = (const char *)server_cert_pem_start,
		.credentials = {
				.authentication = {
				        .certificate = (const char *)client_cert_pem_start,
				        .key = (const char *)client_key_pem_start,
                        .password = "kjdf",
				},
                .username = "esp32",
		}
#else
#if 0
		.broker.address.hostname  = "104.198.23.192",
		.broker.address.port      = 1883,
		.broker.address.transport = MQTT_TRANSPORT_OVER_TCP,
#else
        .broker.address.uri = iotex_dev_access_get_mqtt_connect_addr(),
#endif
#endif
    };

    ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());

    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);

    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(mqtt_client);
}

static void __view_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data)
{
    switch (id)
    {
    case VIEW_EVENT_WIFI_ST:
    {
        ESP_LOGI(TAG, "event: VIEW_EVENT_WIFI_ST");
        struct view_data_wifi_st *p_st = (struct view_data_wifi_st *)event_data;
        if (p_st->is_network)
        {
            net_flag = true;
            ESP_LOGI(TAG, "ESP_MQTT_START");
            mqtt_app_start();
        }
        else
        {
            net_flag = false;
        }
        break;
    }
    // case VIEW_EVENT_SENSOR_DATA:
    // {
    //     if (mqtt_connected_flag == false)
    //     {
    //         break;
    //     }
    //     ESP_LOGI(TAG, "event: VIEW_EVENT_SENSOR_DATA");

    //     struct view_data_sensor_data *p_data = (struct view_data_sensor_data *)event_data;

    //     char data_buf[64];
    //     int len = 0;
    //     memset(data_buf, 0, sizeof(data_buf));

    //     switch (p_data->sensor_type)
    //     {
    //     case SENSOR_DATA_CO2:
    //     {
    //         len = snprintf(data_buf, sizeof(data_buf), "{\"%s\":\"%d\"}", CONFIG_SENSOR_BUILDIN_CO2_VALUE_KEY, (int)p_data->vaule);
    //         esp_mqtt_client_publish(mqtt_client, CONFIG_SENSOR_BUILDIN_TOPIC_DATA, data_buf, len, 0, 0);
    //         break;
    //     }
    //     case SENSOR_DATA_TVOC:
    //     {
    //         len = snprintf(data_buf, sizeof(data_buf), "{\"%s\":\"%d\"}", CONFIG_SENSOR_BUILDIN_TVOC_VALUE_KEY, (int)p_data->vaule);
    //         esp_mqtt_client_publish(mqtt_client, CONFIG_SENSOR_BUILDIN_TOPIC_DATA, data_buf, len, 0, 0);
    //         break;
    //     }
    //     case SENSOR_DATA_TEMP:
    //     {
    //         len = snprintf(data_buf, sizeof(data_buf), "{\"%s\":\"%.1f\"}", CONFIG_SENSOR_BUILDIN_TEMP_VALUE_KEY, p_data->vaule);
    //         esp_mqtt_client_publish(mqtt_client, CONFIG_SENSOR_BUILDIN_TOPIC_DATA, data_buf, len, 0, 0);
    //         break;
    //     }
    //     case SENSOR_DATA_HUMIDITY:
    //     {
    //         len = snprintf(data_buf, sizeof(data_buf), "{\"%s\":\"%d\"}", CONFIG_SENSOR_BUILDIN_HUMIDITY_VALUE_KEY, (int)p_data->vaule);
    //         esp_mqtt_client_publish(mqtt_client, CONFIG_SENSOR_BUILDIN_TOPIC_DATA, data_buf, len, 0, 0);
    //         break;
    //     }
    //     default:
    //         break;
    //     }
    //     break;
    // }

    default:
        break;
    }
}

static void iotex_devnet_upload_task(void *arg)
{
    while (1)
    {
        vTaskDelay(5000 / portTICK_PERIOD_MS);
        iotex_devnet_upload_data_example_json();

        vTaskDelay(5000 / portTICK_PERIOD_MS);
        iotex_devnet_upload_data_example_pb();

        vTaskDelay(5000 / portTICK_PERIOD_MS);
        iotex_devnet_upload_data_example_raw();
    }
}

int indicator_wsiot_init(void)
{

    ESP_ERROR_CHECK(esp_event_handler_instance_register_with(view_event_handle,
                                                             VIEW_EVENT_BASE, VIEW_EVENT_WIFI_ST,
                                                             __view_event_handler, NULL, NULL));

    // ESP_ERROR_CHECK(esp_event_handler_instance_register_with(view_event_handle,
    //                                                          VIEW_EVENT_BASE, VIEW_EVENT_SENSOR_DATA,
    //                                                          __view_event_handler, NULL, NULL));

    // TODO: Initialize NVS on indicator_storage_init (make them work)
    while(net_flag == false){
        vTaskDelay(1500 / portTICK_PERIOD_MS);
        ESP_LOGI(TAG, "Waiting for network connection...");
    }

#pragma region Time
    /* Alignment Time */
    time_t now = 0;
    struct tm timeinfo = {0};
    time(&now);
    localtime_r(&now, &timeinfo);
    // Is time set? If not, tm_year will be (1970 - 1900).
    if (timeinfo.tm_year < (2016 - 1900))
    {
        ESP_LOGI(TAG, "Time is not set yet. Connecting to WiFi and getting time over NTP.");
        obtain_time();
        // update 'now' variable with current time
        time(&now);
    }

    char strftime_buf[64];
    // Set timezone to China Standard Time
    setenv("TZ", "CST-8", 1);
    tzset();
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The current date/time in Shanghai is: %s", strftime_buf);
#pragma endregion

    iotex_wsiotsdk_init(iotex_time_set_func, iotex_mqtt_pubscription, iotex_mqtt_subscription); // Initialize the WSIOTSDK

    default_SetSeed(esp_random()); // TODO: SetSeed
    iotex_import_key_example();

    xTaskCreate(iotex_devnet_upload_task, "iotex_devnet_upload_task", 1024*4, NULL, 4, NULL);
}
