/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_PROCESSING_H
#define PKCS11_TA_PROCESSING_H

#include <tee_internal_api.h>
#include <pkcs11_attributes.h>

struct pkcs11_session;
struct pkcs11_object;
struct active_processing;

/*
 * Entry points from PKCS11 TA invocation commands
 */

uint32_t entry_import_object(uintptr_t teesess, TEE_Param *ctrl,
			     TEE_Param *in, TEE_Param *out);

uint32_t entry_generate_secret(uintptr_t teesess, TEE_Param *ctrl,
			       TEE_Param *in, TEE_Param *out);

uint32_t entry_generate_key_pair(uintptr_t teesess, TEE_Param *ctrl,
				 TEE_Param *in, TEE_Param *out);

uint32_t entry_processing_init(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out,
				enum processing_func function);

uint32_t entry_processing_step(uintptr_t tee_session, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out,
				enum processing_func function,
				enum processing_step step);

/* verify_oneshot is specific since it get 2 input data buffers */
uint32_t entry_verify_oneshot(uintptr_t tee_session, TEE_Param *ctrl,
				  TEE_Param *in1, TEE_Param *in2,
				  enum processing_func function,
				  enum processing_step step);

uint32_t entry_derive_key(uintptr_t teesess, TEE_Param *ctrl,
			  TEE_Param *in, TEE_Param *out);

/*
 * Util
 */
size_t get_object_key_bit_size(struct pkcs11_object *obj);

void release_active_processing(struct pkcs11_session *session);

uint32_t alloc_get_tee_attribute_data(TEE_ObjectHandle tee_obj,
					     uint32_t attribute,
					     void **data, size_t *size);

uint32_t tee2pkcs_add_attribute(struct pkcs11_attrs_head **head,
				uint32_t pkcs11_id, TEE_ObjectHandle tee_obj,
				uint32_t tee_id);

/*
 * Symmetric crypto algorithm specific functions
 */
bool processing_is_tee_symm(uint32_t proc_id);

uint32_t init_symm_operation(struct pkcs11_session *session,
				enum processing_func function,
				struct pkcs11_attribute_head *proc_params,
				struct pkcs11_object *key);

uint32_t step_symm_operation(struct pkcs11_session *session,
				enum processing_func function,
				enum processing_step step,
				TEE_Param *io1, TEE_Param *io2);

void tee_release_ctr_operation(struct active_processing *processing);
uint32_t tee_init_ctr_operation(struct active_processing *processing,
				    void *proc_params, size_t params_size);

uint32_t tee_ae_decrypt_update(struct active_processing *processing,
			       void *in, size_t in_size);

uint32_t tee_ae_decrypt_final(struct active_processing *processing,
			      void *out, uint32_t *out_size);

uint32_t tee_ae_encrypt_final(struct active_processing *processing,
			      void *out, uint32_t *out_size);

void tee_release_ccm_operation(struct active_processing *processing);
uint32_t tee_init_ccm_operation(struct active_processing *processing,
				    void *proc_params, size_t params_size);

void tee_release_gcm_operation(struct active_processing *processing);
uint32_t tee_init_gcm_operation(struct active_processing *processing,
				    void *proc_params, size_t params_size);

/*  Asymmetric key operations util */
bool processing_is_tee_asymm(uint32_t proc_id);

uint32_t init_asymm_operation(struct pkcs11_session *session,
				enum processing_func function,
				struct pkcs11_attribute_head *proc_params,
				struct pkcs11_object *obj);

uint32_t do_symm_derivation(struct pkcs11_session *session,
			     struct pkcs11_attribute_head *proc_params,
			     struct pkcs11_object *parent_key,
			     struct pkcs11_attrs_head **head);

uint32_t step_asymm_operation(struct pkcs11_session *session,
			      enum processing_func function,
			      enum processing_step step,
			      TEE_Param *io1, TEE_Param *io2);

uint32_t do_asymm_derivation(struct pkcs11_session *session,
			     struct pkcs11_attribute_head *proc_params,
			     struct pkcs11_attrs_head **head);


/*
 * Elliptic curve crypto algorithm specific functions
 */
uint32_t load_tee_ec_key_attrs(TEE_Attribute **tee_attrs, size_t *tee_count,
				struct pkcs11_object *obj);

size_t ec_params2tee_keysize(void *attr, size_t size);

uint32_t ec_params2tee_curve(void *attr, size_t size);

uint32_t pkcs2tee_algo_ecdh(uint32_t *tee_id,
			   struct pkcs11_attribute_head *proc_params,
			   struct pkcs11_object *obj);

uint32_t pkcs2tee_ecdh_param_pub(struct pkcs11_attribute_head *proc_params,
			        void **pub_data, size_t *pub_size);

uint32_t pkcs2tee_algo_ecdsa(uint32_t *tee_id,
			   struct pkcs11_attribute_head *proc_params,
			   struct pkcs11_object *obj);

uint32_t generate_ec_keys(struct pkcs11_attribute_head *proc_params,
			  struct pkcs11_attrs_head **pub_head,
			  struct pkcs11_attrs_head **priv_head);

/*
 * RSA crypto algorithm specific functions
 */
uint32_t load_tee_rsa_key_attrs(TEE_Attribute **tee_attrs, size_t *tee_count,
				struct pkcs11_object *obj);

uint32_t pkcs2tee_proc_params_rsa_pss(struct active_processing *processing,
				     struct pkcs11_attribute_head *proc_params);

void tee_release_rsa_pss_operation(struct active_processing *processing);

uint32_t pkcs2tee_algo_rsa_pss(uint32_t *tee_id,
				struct pkcs11_attribute_head *proc_params);

uint32_t pkcs2tee_algo_rsa_oaep(uint32_t *tee_id,
				struct pkcs11_attribute_head *proc_params);

uint32_t tee_init_rsa_aes_key_wrap_operation(struct active_processing *proc,
					     void *proc_params,
					     size_t params_size);

uint32_t generate_rsa_keys(struct pkcs11_attribute_head *proc_params,
			   struct pkcs11_attrs_head **pub_head,
			   struct pkcs11_attrs_head **priv_head);

#endif /*PKCS11_TA_PROCESSING_H*/
