/* psa_api_stub.c - auto-generated for test linkage */
#include <psa/crypto.h>

extern int wolfPSA_CryptoIsInitialized(void);

static psa_status_t wolfPSA_StubNotSupported(void)
{
    if (!wolfPSA_CryptoIsInitialized()) {
        return PSA_ERROR_BAD_STATE;
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_pake_abort(psa_pake_operation_t *operation) {
    (void)operation;
    return wolfPSA_StubNotSupported();
}

psa_algorithm_t psa_pake_cs_get_algorithm(const psa_pake_cipher_suite_t *cipher_suite) {
    (void)cipher_suite;
    return 0;
}

void psa_pake_cs_set_algorithm(psa_pake_cipher_suite_t *cipher_suite, psa_algorithm_t alg) {
    (void)cipher_suite;
    (void)alg;
}

psa_pake_primitive_t psa_pake_cs_get_primitive(const psa_pake_cipher_suite_t *cipher_suite) {
    (void)cipher_suite;
    return 0;
}

void psa_pake_cs_set_primitive(psa_pake_cipher_suite_t *cipher_suite,
                               psa_pake_primitive_t primitive) {
    (void)cipher_suite;
    (void)primitive;
}

uint32_t psa_pake_cs_get_key_confirmation(const psa_pake_cipher_suite_t *cipher_suite) {
    (void)cipher_suite;
    return PSA_PAKE_UNCONFIRMED_KEY;
}

void psa_pake_cs_set_key_confirmation(psa_pake_cipher_suite_t *cipher_suite,
                                      uint32_t key_confirmation) {
    (void)cipher_suite;
    (void)key_confirmation;
}

psa_status_t psa_pake_get_shared_key(psa_pake_operation_t *operation, const psa_key_attributes_t *attributes, psa_key_id_t *key) {
    (void)operation;
    (void)attributes;
    (void)key;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_input(psa_pake_operation_t *operation, psa_pake_step_t step, const uint8_t *input, size_t input_length) {
    (void)operation;
    (void)step;
    (void)input;
    (void)input_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_output(psa_pake_operation_t *operation, psa_pake_step_t step, uint8_t *output, size_t output_size, size_t *output_length) {
    (void)operation;
    (void)step;
    (void)output;
    (void)output_size;
    (void)output_length;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_set_context(psa_pake_operation_t *operation, const uint8_t *context, size_t context_len) {
    (void)operation;
    (void)context;
    (void)context_len;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_set_peer(psa_pake_operation_t *operation, const uint8_t *peer_id, size_t peer_id_len) {
    (void)operation;
    (void)peer_id;
    (void)peer_id_len;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_set_role(psa_pake_operation_t *operation, psa_pake_role_t role) {
    (void)operation;
    (void)role;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_set_user(psa_pake_operation_t *operation, const uint8_t *user_id, size_t user_id_len) {
    (void)operation;
    (void)user_id;
    (void)user_id_len;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_pake_setup(psa_pake_operation_t *operation, psa_key_id_t password_key, const psa_pake_cipher_suite_t *cipher_suite) {
    (void)operation;
    (void)password_key;
    (void)cipher_suite;
    return wolfPSA_StubNotSupported();
}

psa_status_t psa_purge_key(psa_key_id_t key) {
    (void)key;
    return wolfPSA_StubNotSupported();
}

void psa_reset_key_attributes(psa_key_attributes_t *attributes) {
    if (attributes == NULL) {
        return;
    }

    *attributes = psa_key_attributes_init();
}
