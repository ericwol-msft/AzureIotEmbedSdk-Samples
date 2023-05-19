#include <stdio.h>
#include <stdlib.h>
#include <azure/az_core.h>
#include <azure/az_iot.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

char password[256];
static uint32_t iot_hub_sas_key_expiration_hours = 2;
static uint32_t get_epoch_expiration_time(uint32_t hours);
//az_result sample_base64_decode(az_span base64_encoded, az_span in_span, az_span* out_span);
//az_result sample_base64_encode(az_span bytes, az_span in_span, az_span* out_span);
az_result sample_hmac_sha256_sign(az_span key, az_span bytes, az_span in_span, az_span* out_span);

az_result generate_sas_key(az_span iot_hub_hostname, az_span device_id, az_span device_key)
{
    static char sas_b64_decoded_key[32];
    static char sas_signature_buf[128];
    static char sas_signature_hmac_encoded_buf[128] = { 0 };
    static char sas_signature_encoded_buf_b64[128] = { 0 };

    az_result res;
    az_iot_hub_client client;
    res = az_iot_hub_client_init(&client, iot_hub_hostname, device_id, NULL);
    if (az_result_failed(res))
    {
        return res;
    }

    // Create the POSIX expiration time from input hours
    uint32_t sas_expiration = get_epoch_expiration_time(iot_hub_sas_key_expiration_hours);

    // Decode the base64 encoded SAS key to use for HMAC signing
    int32_t out_written;
    if (az_result_failed(
        res = az_base64_decode(AZ_SPAN_FROM_BUFFER(sas_b64_decoded_key), device_key, &out_written)))
    {
        printf("Could not decode the SAS key: return code %d\n", res);
        return res;
    }

    // Get the signature which will be signed with the decoded key
    az_span sas_signature_span;
    if (az_result_failed(
        res = az_iot_hub_client_sas_get_signature(
            &client,
            sas_expiration,
            AZ_SPAN_FROM_BUFFER(sas_signature_buf),
            &sas_signature_span)))
    {
        printf("Could not get the signature for SAS key: return code %d\n", res);
        return res;
    }

    // HMAC-SHA256 sign the signature with the decoded key
    az_span hmac256_signed_span = AZ_SPAN_FROM_BUFFER(sas_signature_hmac_encoded_buf);
    if (az_result_failed(
        res = sample_hmac_sha256_sign(
            AZ_SPAN_FROM_BUFFER(sas_b64_decoded_key),
            sas_signature_span,
            hmac256_signed_span,
            &hmac256_signed_span)))
    {
        printf("Could not sign the signature: return code %d\n", res);
        return res;
    }

    // base64 encode the result of the HMAC signing
    if (az_result_failed(
        res = az_base64_encode(
            AZ_SPAN_FROM_BUFFER(sas_signature_encoded_buf_b64),
            hmac256_signed_span,
            &out_written)))
    {
        printf("Could not base64 encode the password: return code %d\n", res);
        return res;
    }

    // Get the resulting password, passing the base64 encoded, HMAC signed bytes
    size_t password_length;
    if (az_result_failed(
        res = az_iot_hub_client_sas_get_password(
            &client,
            sas_expiration,
            az_span_create(sas_signature_encoded_buf_b64, out_written),
            AZ_SPAN_EMPTY,
            password,
            sizeof(password),
            &password_length)))
    {
        printf("Could not get the password: return code %d\n", res);
        return res;
    }

    return AZ_OK;
}

static uint32_t get_epoch_expiration_time(uint32_t hours)
{
    return (uint32_t)((uint32_t)time(NULL) + hours * 60L * 60L);
}

// HMAC256 an input span with an input key
az_result sample_hmac_sha256_sign(az_span key, az_span bytes, az_span in_span, az_span* out_span)
{
    az_result result;

    unsigned int hmac_encode_len = 0;
    unsigned char* hmac = HMAC(
        EVP_sha256(),
        (void*)az_span_ptr(key),
        az_span_size(key),
        az_span_ptr(bytes),
        (size_t)az_span_size(bytes),
        az_span_ptr(in_span),
        &hmac_encode_len);

    if (hmac != NULL)
    {
        *out_span = az_span_create(az_span_ptr(in_span), (int32_t)hmac_encode_len);
        result = AZ_OK;
    }
    else
    {
        result = AZ_ERROR_NOT_ENOUGH_SPACE;
    }

    return result;
}
