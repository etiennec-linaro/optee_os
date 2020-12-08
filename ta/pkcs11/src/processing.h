/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_PROCESSING_H
#define PKCS11_TA_PROCESSING_H

#include <pkcs11_attributes.h>
#include <tee_internal_api.h>

struct pkcs11_client;
struct pkcs11_session;
struct pkcs11_object;
struct active_processing;

/*
 * Entry points from PKCS11 TA invocation commands
 */

enum pkcs11_rc entry_generate_secret(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_generate_key_pair(struct pkcs11_client *client,
				       uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_processing_init(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params,
				     enum processing_func function);

enum pkcs11_rc entry_processing_step(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params,
				     enum processing_func function,
				     enum processing_step step);

/* verify_oneshot is specific since it get 2 input data buffers */
enum pkcs11_rc entry_verify_oneshot(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params,
				    enum processing_func function,
				    enum processing_step step);

enum pkcs11_rc entry_derive_key(struct pkcs11_client *client,
				uint32_t ptypes, TEE_Param *params);

/*
 * Util
 */
size_t get_object_key_bit_size(struct pkcs11_object *obj);

void release_active_processing(struct pkcs11_session *session);

enum pkcs11_rc alloc_get_tee_attribute_data(TEE_ObjectHandle tee_obj,
					    uint32_t attribute,
					    void **data, size_t *size);

enum pkcs11_rc tee2pkcs_add_attribute(struct obj_attrs **head,
				      uint32_t pkcs11_id, TEE_ObjectHandle tee_obj,
				      uint32_t tee_id);

/*
 * Symmetric crypto algorithm specific functions
 */
bool processing_is_tee_symm(uint32_t proc_id);

enum pkcs11_rc init_symm_operation(struct pkcs11_session *session,
				   enum processing_func function,
				   struct pkcs11_attribute_head *proc_params,
				   struct pkcs11_object *key);

enum pkcs11_rc step_symm_operation(struct pkcs11_session *session,
				   enum processing_func function,
				   enum processing_step step,
				   uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc tee_init_ctr_operation(struct active_processing *processing,
				      void *proc_params, size_t params_size);

enum pkcs11_rc tee_ae_decrypt_update(struct active_processing *processing,
				     void *in, size_t in_size);

enum pkcs11_rc tee_ae_decrypt_final(struct active_processing *processing,
				    void *out, uint32_t *out_size);

enum pkcs11_rc tee_ae_encrypt_final(struct active_processing *processing,
				    void *out, uint32_t *out_size);

void tee_release_ccm_operation(struct active_processing *processing);
enum pkcs11_rc tee_init_ccm_operation(struct active_processing *processing,
				      void *proc_params, size_t params_size);

void tee_release_gcm_operation(struct active_processing *processing);
enum pkcs11_rc tee_init_gcm_operation(struct active_processing *processing,
				      void *proc_params, size_t params_size);

/*  Asymmetric key operations util */
bool processing_is_tee_asymm(uint32_t proc_id);

enum pkcs11_rc init_asymm_operation(struct pkcs11_session *session,
				    enum processing_func function,
				    struct pkcs11_attribute_head *proc_params,
				    struct pkcs11_object *obj);

enum pkcs11_rc do_symm_derivation(struct pkcs11_session *session,
				  struct pkcs11_attribute_head *proc_params,
				  struct pkcs11_object *parent_key,
				  struct obj_attrs **head);

enum pkcs11_rc step_asymm_operation(struct pkcs11_session *session,
				    enum processing_func function,
				    enum processing_step step,
				    uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc do_asymm_derivation(struct pkcs11_session *session,
				   struct pkcs11_attribute_head *proc_params,
				   struct obj_attrs **head);


/*
 * Elliptic curve crypto algorithm specific functions
 */
enum pkcs11_rc load_tee_ec_key_attrs(TEE_Attribute **tee_attrs, size_t *tee_count,
				     struct pkcs11_object *obj);

size_t ec_params2tee_keysize(void *attr, size_t size);

uint32_t ec_params2tee_curve(void *attr, size_t size);

enum pkcs11_rc pkcs2tee_algo_ecdh(uint32_t *tee_id,
				  struct pkcs11_attribute_head *proc_params,
				  struct pkcs11_object *obj);

enum pkcs11_rc pkcs2tee_ecdh_param_pub(struct pkcs11_attribute_head *params,
				       void **pub_data, size_t *pub_size);

enum pkcs11_rc pkcs2tee_algo_ecdsa(uint32_t *tee_id,
				   struct pkcs11_attribute_head *proc_params,
				   struct pkcs11_object *obj);

enum pkcs11_rc generate_ec_keys(struct pkcs11_attribute_head *proc_params,
				struct obj_attrs **pub_head,
				struct obj_attrs **priv_head);

size_t ecdsa_get_input_max_byte_size(TEE_OperationHandle op);

/*
 * RSA crypto algorithm specific functions
 */
enum pkcs11_rc load_tee_rsa_key_attrs(TEE_Attribute **tee_attrs,
				      size_t *tee_count,
				      struct pkcs11_object *obj);

enum pkcs11_rc pkcs2tee_proc_params_rsa_pss(struct active_processing *proc,
					    struct pkcs11_attribute_head *par);

enum pkcs11_rc pkcs2tee_algo_rsa_pss(uint32_t *tee_id,
				     struct pkcs11_attribute_head *params);

enum pkcs11_rc pkcs2tee_algo_rsa_oaep(uint32_t *tee_id,
				      struct pkcs11_attribute_head *params);

enum pkcs11_rc tee_init_rsa_aes_key_wrap_operation(struct active_processing *proc,
					           void *params, size_t params_size);

enum pkcs11_rc generate_rsa_keys(struct pkcs11_attribute_head *proc_params,
				 struct obj_attrs **pub_head,
				 struct obj_attrs **priv_head);

#endif /*PKCS11_TA_PROCESSING_H*/
