#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <azure/az_core.h>
#include <azure/az_iot.h>
#include <azure/storage/az_storage_blobs.h>
#include <azure/core/az_json.h>


#define IOT_HUB_VERSION "2020-03-01"


static az_span iot_hub_hostname = AZ_SPAN_LITERAL_FROM_STR("yourhub.azure-devices.net");
static az_span device_id = AZ_SPAN_LITERAL_FROM_STR("<device_id>");
static az_span device_key = AZ_SPAN_LITERAL_FROM_STR("<device_key>");
static az_span content_to_upload = AZ_SPAN_LITERAL_FROM_STR("Some test content");

static az_result request_blob_info_from_hub();
static az_result upload_data_to_blob_storage();
static az_result notify_hub_upload_finished(az_result operationResult);
extern az_result generate_sas_key(az_span iot_hub_hostname, az_span device_id, az_span device_key);
extern char password[256];
char correlation_id_buf[256];
char storage_host_name_buf[256];
char blob_container_name_buf[256];
char blob_name_buf[256];
char sas_token_buf[256];


int main()
{
    // create a SAS key to access the hub
    az_result result = generate_sas_key(iot_hub_hostname, device_id, device_key);
    if (az_result_failed(result))
    {
        printf("Failed to generate sas key\n");
        return result;
    }

    result = request_blob_info_from_hub();
    if (az_result_succeeded(result))
    {
        result = upload_data_to_blob_storage();
        // always tells the hub when the upload is done (succeeded or failed)
        if (az_result_succeeded(notify_hub_upload_finished(result)))
        {
            printf("file upload succeeded\n");
        }
    }
}

az_result request_blob_info_from_hub()
{
    az_span remainder = { 0 };
    uint8_t response_buffer[1024] = { 0 };
    az_http_response http_response;
    az_result result = az_http_response_init(&http_response, AZ_SPAN_FROM_BUFFER(response_buffer));
    if (az_result_failed(result))
    {
        printf("az_http_response_init failed\n");
        return result;
    }

    // build the request payload
    char payload_buf[256];
    snprintf(payload_buf, sizeof(payload_buf), "{ \"blobName\": \"%u\" }", (unsigned long)time(NULL));

    uint8_t header_buf[1024];
    uint8_t url_buf[1024];
    az_span url = AZ_SPAN_FROM_BUFFER(url_buf);
    remainder = az_span_copy(url, AZ_SPAN_FROM_STR("https://"));
    remainder = az_span_copy(remainder, iot_hub_hostname);
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR("/devices/"));
    remainder = az_span_copy(remainder, device_id);
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR("/files"));
    az_span_copy_u8(remainder, 0);

    az_http_request request = { 0 };
    result = az_http_request_init(&request, &az_context_application, az_http_method_post(), url,
        (int32_t)strlen(az_span_ptr(url)), AZ_SPAN_FROM_BUFFER(header_buf), AZ_SPAN_FROM_BUFFER(payload_buf));
    if (az_result_failed(result))
    {
        printf("az_http_request_init failed\n");
        return result;
    }

    result = az_http_request_set_query_parameter(&request, AZ_SPAN_FROM_STR("api-version"), AZ_SPAN_FROM_STR(IOT_HUB_VERSION), false);
    if (az_result_failed(result))
    {
        printf("az_http_request_set_query_parameter failed\n");
        return result;
    }

    result = az_http_request_append_header(&request, AZ_SPAN_FROM_STR("Authorization"), az_span_create_from_str(password));
    if (az_result_failed(result))
    {
        printf("az_http_request_append_header failed\n");
        return result;
    }

    result = az_http_request_append_header(&request, AZ_SPAN_FROM_STR("Content-Type"), AZ_SPAN_FROM_STR("application/json; charset=utf-8"));
    if (az_result_failed(result))
    {
        printf("az_http_request_append_header failed\n");
        return result;
    }

    result = az_http_client_send_request(&request, &http_response);
    if (az_result_failed(result))
    {
        printf("az_http_client_send_request failed\n");
        return result;
    }

    az_http_response_status_line status_line = { 0 };
    result = az_http_response_get_status_line(&http_response, &status_line);
    if (az_result_failed(result))
    {
        printf("az_http_response_get_status_line failed\n");
        return result;
    }

    if (status_line.status_code != AZ_HTTP_STATUS_CODE_OK)
    {
        printf("invalid http code: %d\n", status_line.status_code);
        return AZ_ERROR_HTTP_INVALID_STATE;
    }

    az_span body = { 0 };
    result = az_http_response_get_body(&http_response, &body);
    if (az_result_failed(result))
    {
        printf("az_http_response_get_body failed\n");
        return result;
    }


    // hub payload json parse

    const az_span correlation_id_tag = AZ_SPAN_LITERAL_FROM_STR("correlationId");
    const az_span host_name_tag = AZ_SPAN_LITERAL_FROM_STR("hostName");
    const az_span container_name_tag = AZ_SPAN_LITERAL_FROM_STR("containerName");
    const az_span blob_name_tag = AZ_SPAN_LITERAL_FROM_STR("blobName");
    const az_span sas_token_tag = AZ_SPAN_LITERAL_FROM_STR("sasToken");

    az_json_reader json_reader;
    result = az_json_reader_init(&json_reader, body, NULL);
    if (az_result_failed(result))
    {
        printf("az_json_parser_init failed\n");
        return result;
    }

    result = az_json_reader_next_token(&json_reader);
    if (az_result_failed(result) || json_reader.token.kind != AZ_JSON_TOKEN_BEGIN_OBJECT)
    {
        printf("az_json_reader_next_token failed\n");
        return result;
    }

    while (az_result_succeeded(result))
    {
        result = az_json_reader_next_token(&json_reader);
        if (az_result_succeeded(result))
        {
            if (json_reader.token.kind == AZ_JSON_TOKEN_PROPERTY_NAME &&
                az_json_token_is_text_equal(&json_reader.token, correlation_id_tag))
            {
                result = az_json_reader_next_token(&json_reader);
                if (az_result_succeeded(result) && json_reader.token.kind == AZ_JSON_TOKEN_STRING)
                {
                    result = az_json_token_get_string(&json_reader.token, correlation_id_buf, sizeof(correlation_id_buf), NULL);
                }
            }
            else if (json_reader.token.kind == AZ_JSON_TOKEN_PROPERTY_NAME &&
                az_json_token_is_text_equal(&json_reader.token, host_name_tag))
            {
                result = az_json_reader_next_token(&json_reader);
                if (az_result_succeeded(result) && json_reader.token.kind == AZ_JSON_TOKEN_STRING)
                {
                    result = az_json_token_get_string(&json_reader.token, storage_host_name_buf, sizeof(storage_host_name_buf), NULL);
                }
            }
            else if (json_reader.token.kind == AZ_JSON_TOKEN_PROPERTY_NAME &&
                az_json_token_is_text_equal(&json_reader.token, container_name_tag))
            {
                result = az_json_reader_next_token(&json_reader);
                if (az_result_succeeded(result) && json_reader.token.kind == AZ_JSON_TOKEN_STRING)
                {
                    result = az_json_token_get_string(&json_reader.token, blob_container_name_buf, sizeof(blob_container_name_buf), NULL);
                }
            }
            else if (json_reader.token.kind == AZ_JSON_TOKEN_PROPERTY_NAME &&
                az_json_token_is_text_equal(&json_reader.token, blob_name_tag))
            {
                result = az_json_reader_next_token(&json_reader);
                if (az_result_succeeded(result) && json_reader.token.kind == AZ_JSON_TOKEN_STRING)
                {
                    result = az_json_token_get_string(&json_reader.token, blob_name_buf, sizeof(blob_name_buf), NULL);
                }
            }
            else if (json_reader.token.kind == AZ_JSON_TOKEN_PROPERTY_NAME &&
                az_json_token_is_text_equal(&json_reader.token, sas_token_tag))
            {
                result = az_json_reader_next_token(&json_reader);
                if (az_result_succeeded(result) && json_reader.token.kind == AZ_JSON_TOKEN_STRING)
                {
                    result = az_json_token_get_string(&json_reader.token, sas_token_buf, sizeof(sas_token_buf), NULL);
                }
            }
        }
    }

    return AZ_OK;
}


az_result upload_data_to_blob_storage()
{
    uint8_t response_buffer[1024] = { 0 };
    az_http_response http_response;
    az_result result = az_http_response_init(&http_response, AZ_SPAN_FROM_BUFFER(response_buffer));
    if (az_result_failed(result = az_http_response_init(&http_response, AZ_SPAN_FROM_BUFFER(response_buffer))))
    {
        printf("az_http_response_init failed\n");
        return result;
    }

    // build the blob uri
    az_span remainder = { 0 };
    char requestUri_buf[1024];
    az_span requestUri = AZ_SPAN_FROM_BUFFER(requestUri_buf);
    remainder = az_span_copy(requestUri, AZ_SPAN_FROM_STR("https://"));
    remainder = az_span_copy(remainder, az_span_create_from_str(storage_host_name_buf));
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR("/"));
    remainder = az_span_copy(remainder, az_span_create_from_str(blob_container_name_buf));
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR("/"));
    remainder = az_span_copy(remainder, az_span_create_from_str(blob_name_buf));
    remainder = az_span_copy(remainder, az_span_create_from_str(sas_token_buf));
    remainder = az_span_copy_u8(remainder, 0);


    // 1) Init storage client.
    // Example expects AZURE_STORAGE_URL in env to be a URL w/ SAS token
    az_storage_blobs_blob_client client;
    az_storage_blobs_blob_client_options options = az_storage_blobs_blob_client_options_default();

    result = az_storage_blobs_blob_client_init(&client, requestUri, AZ_CREDENTIAL_ANONYMOUS, &options);
    if (az_result_failed(result))
    {
        printf("az_storage_blobs_blob_client_init failed\n");
        return result;
    }

    // 2) upload content
    result = az_storage_blobs_blob_upload(&client, &az_context_application, content_to_upload, NULL, &http_response);
    if (az_result_failed(result))
    {
        printf("Failed to upload blob\n");
        return result;
    }

    // 3) get response and parse it
    az_http_response_status_line status_line;
    result = az_http_response_get_status_line(&http_response, &status_line);
    if (az_result_failed(result))
    {
        printf("az_http_response_get_status_line failed\n");
        return result;
    }

    if (status_line.status_code != AZ_HTTP_STATUS_CODE_CREATED)
    {
        printf("invalid http code: %d\n", status_line.status_code);
        return AZ_ERROR_HTTP_INVALID_STATE;
    }

    return AZ_OK;
}


az_result notify_hub_upload_finished(az_result operationResult)
{
    az_span remainder = { 0 };
    uint8_t response_buffer[1024] = { 0 };
    az_http_response http_response;
    az_result result = az_http_response_init(&http_response, AZ_SPAN_FROM_BUFFER(response_buffer));
    if (az_result_failed(result))
    {
        printf("az_http_response_init failed\n");
        return result;
    }

    uint8_t header_buf[1024];
    uint8_t url_buf[1024];
    az_span url = AZ_SPAN_FROM_BUFFER(url_buf);
    remainder = az_span_copy(url, AZ_SPAN_FROM_STR("https://"));
    remainder = az_span_copy(remainder, iot_hub_hostname);
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR("/devices/"));
    remainder = az_span_copy(remainder, device_id);
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR("/files/notifications"));
    az_span_copy_u8(remainder, 0);


    char payload_buf[512];
    az_span notification_payload = AZ_SPAN_FROM_BUFFER(payload_buf);
    remainder = az_span_copy(notification_payload, AZ_SPAN_FROM_STR("{\"correlationId\": \""));
    remainder = az_span_copy(remainder, az_span_create_from_str(correlation_id_buf));
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR("\", \"isSuccess\": "));
    remainder = az_span_copy(remainder, az_result_failed(operationResult) ? AZ_SPAN_FROM_STR("false") : AZ_SPAN_FROM_STR("true"));
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR(", \"statusCode\": "));
    remainder = az_span_copy(remainder, az_result_failed(operationResult) ? AZ_SPAN_FROM_STR("500") : AZ_SPAN_FROM_STR("200"));
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR(", \"statusDescription\": \""));
    remainder = az_span_copy(remainder, az_result_failed(operationResult) ? AZ_SPAN_FROM_STR("failed") : AZ_SPAN_FROM_STR("succeeded"));;
    remainder = az_span_copy(remainder, AZ_SPAN_FROM_STR("\"}"));
    az_span_copy_u8(remainder, 0);


    az_http_request request = { 0 };
    result = az_http_request_init(&request, &az_context_application, az_http_method_post(), url, (int32_t)strlen(az_span_ptr(url)),
        AZ_SPAN_FROM_BUFFER(header_buf), az_span_create_from_str(payload_buf));
    if (az_result_failed(result))
    {
        printf("az_http_request_init failed\n");
        return result;
    }

    result = az_http_request_set_query_parameter(&request, AZ_SPAN_FROM_STR("api-version"), AZ_SPAN_FROM_STR(IOT_HUB_VERSION), false);
    if (az_result_failed(result))
    {
        printf("az_http_request_set_query_parameter failed\n");
        return result;
    }

    result = az_http_request_append_header(&request, AZ_SPAN_FROM_STR("Authorization"), az_span_create_from_str(password));
    if (az_result_failed(result))
    {
        printf("az_http_request_append_header failed\n");
        return result;
    }

    result = az_http_request_append_header(&request, AZ_SPAN_FROM_STR("Content-Type"), AZ_SPAN_FROM_STR("application/json; charset=utf-8"));
    if (az_result_failed(result))
    {
        printf("az_http_request_append_header failed\n");
        return result;
    }

    result = az_http_client_send_request(&request, &http_response);
    if (az_result_failed(result))
    {
        printf("az_http_client_send_request failed\n");
        return result;
    }

    az_http_response_status_line status_line;
    result = az_http_response_get_status_line(&http_response, &status_line);
    if (az_result_failed(result))
    {
        printf("az_http_response_get_status_line failed\n");
        return result;
    }

    if (status_line.status_code != AZ_HTTP_STATUS_CODE_NO_CONTENT)
    {
        printf("invalid http code: %d\n", status_line.status_code);
        return AZ_ERROR_HTTP_INVALID_STATE;
    }

    return AZ_OK;
}



