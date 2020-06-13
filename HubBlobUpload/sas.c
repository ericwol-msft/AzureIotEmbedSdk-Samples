#include <stdio.h>
#include <stdlib.h>
#include <az_result.h>
#include <az_span.h>
#include <az_context.h>
#include <az_storage_blobs.h>
#include <az_iot_hub_client.h>
#include <az_json.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

char password[256];
static uint32_t iot_hub_sas_key_expiration_hours = 2;
static uint32_t get_epoch_expiration_time(uint32_t hours);
az_result sample_base64_decode(az_span base64_encoded, az_span in_span, az_span* out_span);
az_result sample_base64_encode(az_span bytes, az_span in_span, az_span* out_span);
az_result sample_hmac_sha256_sign(az_span key, az_span bytes, az_span in_span, az_span* out_span);

az_result generate_sas_key(az_span iot_hub_hostname, az_span device_id, az_span device_key)
{
    static char sas_b64_decoded_key[32];
    static char sas_signature_buf[128];
    static char sas_signature_hmac_encoded_buf[128] = { 0 };
    static char sas_signature_encoded_buf_b64[128] = { 0 };

    az_result res;
    az_iot_hub_client client;

    AZ_RETURN_IF_FAILED(az_iot_hub_client_init(
        &client,
        iot_hub_hostname,
        device_id,
        NULL));


    // Create the POSIX expiration time from input hours
    uint32_t sas_expiration = get_epoch_expiration_time(iot_hub_sas_key_expiration_hours);

    // Decode the base64 encoded SAS key to use for HMAC signing
    az_span decoded_key_span;
    if (az_failed(
        res = sample_base64_decode(
            device_key, AZ_SPAN_FROM_BUFFER(sas_b64_decoded_key), &decoded_key_span)))
    {
        printf("Could not decode the SAS key: return code %d\n", res);
        return res;
    }

    // Get the signature which will be signed with the decoded key
    az_span sas_signature_span;
    if (az_failed(
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
    if (az_failed(
        res = sample_hmac_sha256_sign(
            decoded_key_span,
            sas_signature_span,
            hmac256_signed_span,
            &hmac256_signed_span)))
    {
        printf("Could not sign the signature: return code %d\n", res);
        return res;
    }

    // base64 encode the result of the HMAC signing
    az_span b64_encoded_hmac256_signed_signature;
    if (az_failed(
        res = sample_base64_encode(
            hmac256_signed_span,
            AZ_SPAN_FROM_BUFFER(sas_signature_encoded_buf_b64),
            &b64_encoded_hmac256_signed_signature)))
    {
        printf("Could not base64 encode the password: return code %d\n", res);
        return res;
    }

    // Get the resulting password, passing the base64 encoded, HMAC signed bytes
    size_t password_length;
    if (az_failed(
        res = az_iot_hub_client_sas_get_password(
            &client,
            b64_encoded_hmac256_signed_signature,
            sas_expiration,
            AZ_SPAN_NULL,
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

// Decode an input span from base64 to bytes
az_result sample_base64_decode(az_span base64_encoded, az_span in_span, az_span* out_span)
{
    az_result result;

    BIO* b64_decoder;
    BIO* source_mem_bio;

    memset(az_span_ptr(in_span), 0, (size_t)az_span_size(in_span));

    // Create a BIO filter to process the bytes
    b64_decoder = BIO_new(BIO_f_base64());
    if (b64_decoder == NULL)
    {
        return AZ_ERROR_OUT_OF_MEMORY;
    }

    // Get the source BIO to push through the filter
    source_mem_bio = BIO_new_mem_buf(az_span_ptr(base64_encoded), (int)az_span_size(base64_encoded));
    if (source_mem_bio == NULL)
    {
        BIO_free(b64_decoder);
        return AZ_ERROR_OUT_OF_MEMORY;
    }

    // Push the memory through the filter
    source_mem_bio = BIO_push(b64_decoder, source_mem_bio);
    if (source_mem_bio == NULL)
    {
        BIO_free(b64_decoder);
        BIO_free(source_mem_bio);
        return AZ_ERROR_OUT_OF_MEMORY;
    }

    // Set flags to not have a newline and close the BIO
    BIO_set_flags(source_mem_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(source_mem_bio, BIO_CLOSE);

    // Read the memory which was pushed through the filter
    int read_data = BIO_read(source_mem_bio, az_span_ptr(in_span), az_span_size(in_span));

    // Set the output span
    if (read_data > 0)
    {
        *out_span = az_span_init(az_span_ptr(in_span), (int32_t)read_data);
        result = AZ_OK;
    }
    else
    {
        result = AZ_ERROR_INSUFFICIENT_SPAN_SIZE;
    }

    // Free the BIO chain
    BIO_free_all(source_mem_bio);

    return result;
}

// Encode an input span of bytes to base64
az_result sample_base64_encode(az_span bytes, az_span in_span, az_span* out_span)
{
    az_result result;

    BIO* sink_mem_bio;
    BIO* b64_encoder;
    BUF_MEM* encoded_mem_ptr;

    // Create a BIO filter to process the bytes
    b64_encoder = BIO_new(BIO_f_base64());
    if (b64_encoder == NULL)
    {
        return AZ_ERROR_OUT_OF_MEMORY;
    }

    // Create a memory sink BIO to process bytes to
    sink_mem_bio = BIO_new(BIO_s_mem());
    if (sink_mem_bio == NULL)
    {
        BIO_free(b64_encoder);
        return AZ_ERROR_OUT_OF_MEMORY;
    }

    // Push the sink to the encoder
    b64_encoder = BIO_push(b64_encoder, sink_mem_bio);
    if (b64_encoder == NULL)
    {
        BIO_free(sink_mem_bio);
        BIO_free(b64_encoder);
        return AZ_ERROR_OUT_OF_MEMORY;
    }

    // Set no newline flag for the encoder
    BIO_set_flags(b64_encoder, BIO_FLAGS_BASE64_NO_NL);

    // Write the bytes to be encoded
    int bytes_written = BIO_write(b64_encoder, az_span_ptr(bytes), (int)az_span_size(bytes));
    if (bytes_written < 1)
    {
        BIO_free(sink_mem_bio);
        BIO_free(b64_encoder);
        return AZ_ERROR_OUT_OF_MEMORY;
    }

    // Flush the BIO
    BIO_flush(b64_encoder);

    // Get the pointer to the encoded bytes
    BIO_get_mem_ptr(b64_encoder, &encoded_mem_ptr);

    if ((size_t)az_span_size(in_span) >= encoded_mem_ptr->length)
    {
        // Copy the bytes to the output and initialize output span
        memcpy(az_span_ptr(in_span), encoded_mem_ptr->data, encoded_mem_ptr->length);
        *out_span = az_span_init(az_span_ptr(in_span), (int32_t)encoded_mem_ptr->length);

        result = AZ_OK;
    }
    else
    {
        result = AZ_ERROR_INSUFFICIENT_SPAN_SIZE;
    }

    // Free the BIO chain
    BIO_free_all(b64_encoder);

    return result;
}

// HMAC256 an input span with an input key
az_result sample_hmac_sha256_sign(az_span key, az_span bytes, az_span in_span, az_span* out_span)
{
    az_result result;

    unsigned int hmac_encode_len;
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
        *out_span = az_span_init(az_span_ptr(in_span), (int32_t)hmac_encode_len);
        result = AZ_OK;
    }
    else
    {
        result = AZ_ERROR_INSUFFICIENT_SPAN_SIZE;
    }

    return result;
}
