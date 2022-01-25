/*
INTEL CONFIDENTIAL
Copyright (2019) Intel Corporation

The source code contained or described herein and all documents related to the
source code ("Material") are owned by Intel Corporation or its suppliers or
licensors. Title to the Material remains with Intel Corporation or its suppliers
and licensors. The Material contains trade secrets and proprietary and
confidential information of Intel or its suppliers and licensors. The Material
is protected by worldwide copyright and trade secret laws and treaty provisions.
No part of the Material may be used, copied, reproduced, modified, published,
uploaded, posted, transmitted, distributed, or disclosed in any way without
Intel's prior express written permission.

No license under any patent, copyright, trade secret or other intellectual
property right is granted to or conferred upon you by disclosure or delivery of
the Materials, either expressly, by implication, inducement, estoppel or
otherwise. Any license under such intellectual property rights must be express
and approved by Intel in writing.
*/

#include <stdbool.h>
#include <bitstream.h>
#include <sdm_types.h>
#include <sdm_system.h>
#include <bitstream_parse_section.h>
#include <bitstream_section.h>
#include <bitstream_mod_prevention.h>
#include <cmf_compatible.h>
#include <hal_sdm_br.h>
#include <hal_sdm.h>
#include <sdm_trace.h>
#include <error_codes.h>
#include <stddef.h>
#include <comp_config.h>
#include <pkc.h>
#include <hash_mgr.h>
#include <pin_functions.h>
#include <config_clock.h>
#include <persistent.h>
#include <slot_table_compatible.h>
#include <sdm_fw_info.h>
#include <hal.h>
#include <config_hps.h>
#include <bitstream_action_if.h>
#include <cmf_reload.h>
#include <config_state_machine.h>
#include <ecdsa.h>
#include <sdm_authentication.h>
#include <efuse_interlock.h>
#include <error_codes.h>
#include <sdm_bootrom.h>
#include <crypto_context.h>
#include <config_cnoc_scramble.h>
#include <cmf_designhash.h>
#include <efuse_cmf_access.h>
#include <cmf_security_options.h>
#include <debug_cert.h>
#include <config_aes.h>
#include <error_reporting.h>
#include <power_table.h>
#include <config_cvp.h>
#include <jtag_drv.h>
#include <cmf_system_security.h>
#include <sdm_fw_info.h>
#include <sdm_dft_utils.h>
#ifdef ENABLE_TEST_DEBUG
#include <test_debug.h>
#endif

#ifdef ENABLE_TRACE_BUFFER
#include <trace_buffer.h>
#endif

#if defined(ENABLE_AFRL_ATTESTATION) || defined(ENABLE_PLATFORM_ATTESTATION)
#include <sdm_attest.h>
#include <afrl_measurements.h>
#endif

#ifdef HAL_FALCONMESA
#ifdef CMF_AUTH_VAB
#include <vab_preauth.h>
#endif
#endif

#ifdef ENABLE_ANTI_TAMPER
#include <anti_tamper.h>
#endif

#ifdef ENABLE_PLATFORM_ATTESTATION
#include <pa_public.h>
#endif

// Memory to hold main and signature descriptor
__attribute__((section(".handoff_main_descriptor_ram_values"))) main_descriptor_t g_main_header __attribute__ ((aligned(8)));
__attribute__((section(".handoff_signature_descriptor_ram_values"))) signature_descriptor_t g_signature_descriptor __attribute__ ((aligned(8)));

extern cfg_state_t g_config_state;
static bool cmf_main_descriptor_valid(const main_descriptor_t *p_descriptor);
static uint32_t parse_main_descriptor(comp_config_handle_t comp_handle, const main_descriptor_t *main_descriptor);
static sdm_return_t state_cmf_transition(const main_descriptor_t *p_main_header, const signature_descriptor_t *p_signature_descriptor);

#ifdef HAL_FALCONMESA
static bool create_19x_handoff_data(void);

#define DECOMP_STUB_19X_ENTRY               0x176050
#define CMFD_LOAD_ADDR_OFFSET               0x0484
#define CMFD_ENTRY_ADDR_OFFSET              0x047C
#define HANDOFF_19X_DEST_ADDR               0x17BC80
#define TRACE_BUFF_19X_DEST_ADDR            0x17B000
#define MAIN_HEADER_19X_DEST_ADDR           0x17A000
#define SIG_DESCRIPTOR_19X_DEST_ADDR        0x179000

/*!
@brief Copy handoff data structures to locations expected by 19.x memory map.
       Does nothing if the target cmf is not 19.x.

@return true  = the target cmf is 19.x.
        false = the target cmf is not 19.x
 */
static bool create_19x_handoff_data(void)
{
    uint32_t const * const pg_main_header = (uint32_t const * const)&g_main_header;

    //Step 1: Check if we're transitioning into 19.x
    if((pg_main_header[CMFD_LOAD_ADDR_OFFSET / sizeof(uint32_t)] + pg_main_header[CMFD_ENTRY_ADDR_OFFSET / sizeof(uint32_t)]) != DECOMP_STUB_19X_ENTRY)
    {
        // No transition to 19.x, do nothing and bail out.
        return false;
    }

    // Step 2: Copy g_cmf_handoff_data to where 19.x expects (old memory map)
    sdm_memcpy((void * const)HANDOFF_19X_DEST_ADDR, sizeof(cmf_handoff_data_t), (void * const)g_persistent_data->p_handoff_data, sizeof(cmf_handoff_data_t));

#ifdef ENABLE_TRACE_BUFFER
    //Step 3: Copy g_trace to where 19.x expects (old memory map)
    sdm_memcpy((void * const)TRACE_BUFF_19X_DEST_ADDR, sizeof(trace_buffer_t), (void * const)&g_trace, sizeof(trace_buffer_t));
#endif

    // Step 4: Copy g_main_header to where 19.x expects (old memory map) 
    sdm_memcpy((void * const)MAIN_HEADER_19X_DEST_ADDR, sizeof(altr_common_fw_header_t), (void * const)&g_main_header, sizeof(altr_common_fw_header_t));

    // Step 5: Copy g_signature_descriptor to where 19.x expects (old memory map).
    sdm_memcpy((void * const)SIG_DESCRIPTOR_19X_DEST_ADDR, sizeof(signature_descriptor_t), (void * const)&g_signature_descriptor, sizeof(signature_descriptor_t));

    // Set p_handoff_data in persistent data to point to new area.
    persistent_set_handoff_pointer((cmf_handoff_data_t *)HANDOFF_19X_DEST_ADDR);

    return true;
}
#endif  //PLATFORM_FALCONMESA && FM6_REV_A

STATIC void config_drv_handles_for_authentication(comp_config_handle_t comp_config_handle,
                                                  crypto_context_t *p_sdm_auth_context)
{
    //
    // configure the authentication context with the hw resources required for authentication
    // operations.  These driver handles are confirmed to be != INVALID_HANDLE in
    // sdm_authenticate(), so no need to do that here.
    //
    p_sdm_auth_context->dma_handle = comp_config_dma_handle_get(comp_config_handle);
    p_sdm_auth_context->in_buf_handle = comp_config_inbuf_handle_get(comp_config_handle);
    p_sdm_auth_context->sha_handle = comp_config_sha_handle_get(comp_config_handle);
    p_sdm_auth_context->pkc_handle = comp_config_pkc_handle_get(comp_config_handle);
}

/*!
This function is used to detect if a descriptor is a valid Main descriptor.
The return of false from this function only indicates that the descriptor has valid
members to allow continued processing of this descriptor as a main_descriptor_t structure.
If this is any other type of descriptor or if this descriptor has invalid members then
this function returns false.

@param p_descriptor is the descriptor to check for validity.

@return Returns true if this was an RMA/Engineering descriptor that can be further processed
and false if this descriptor was not a valid RMA/Engineering descriptor.
 */
static bool cmf_main_descriptor_valid(const main_descriptor_t *p_descriptor)
{
    bool ret = false;

#if 0
    if(cmf_ram_ptr_valid(p_descriptor) == false)
    {
        return false;
    }
#endif

    /*
      Make sure that the basics are correct for this header type.
     */
    if(p_descriptor->magic_number == MAIN_DESCRIPTOR_MAGIC_NUMBER)
    {
        if( (g_config_state.pr_bitstream_only == false) &&
            ((p_descriptor->desc_type == DESC_TYPE_IO) ||
            (p_descriptor->desc_type == DESC_TYPE_CORE) ||
            (p_descriptor->desc_type == DESC_TYPE_HPS) ||
            (p_descriptor->desc_type == DESC_TYPE_HPIO) ||
            (p_descriptor->desc_type == DESC_TYPE_PR) ||
            (p_descriptor->desc_type == DESC_TYPE_ASIC) ||
            (p_descriptor->desc_type == DESC_TYPE_CERT) ||
            (p_descriptor->desc_type == DESC_TYPE_FBRC)))
        {
            ret = true;
        }
        else if((g_config_state.pr_bitstream_only == true) &&
                ((p_descriptor->desc_type == DESC_TYPE_PR) ||
                 (p_descriptor->desc_type == DESC_TYPE_CERT)))
        {
            ret = true;
            config_state_set_pr_bitstream_only(false);
        }
        else if((is_test_fw()) &&
                (p_descriptor->desc_type == DESC_TYPE_TEST))
        {
            ret = true;
        }
        else
        {
            //if ever hit into this case, pr_bitstream_only flag
            //is cleared in wipe state.
            //config_state_set_pr_bitstream_only(false);
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
        }

        //
        // Check if the Version number is non zero. Reject if the version number is not equal to 0
        //
        if((p_descriptor->public_version.build != 0) ||
           (p_descriptor->public_version.major != 0) ||
           (p_descriptor->public_version.minor != 0))
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return false;
        }
		
#if defined(FEAT_DYNAMIC_CVP_LOCATION)
        //update CVP AIB Addr (FM only) in IO section
        if (p_descriptor->desc_type == DESC_TYPE_IO)
        {
            if (cvp_aib_protect_mask_set(p_descriptor->cvp_protect_mask) != SDM_SUCCESS)
            {
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);                
                return false;
            }
        }
#endif
		
    }
    else if(p_descriptor->magic_number == ALTR_COMMON_BR_HEADER_MAGIC)
    {
        ret = true;
    }
    else
    {
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
    }

    return ret;
}

main_descriptor_t* bitstream_parse_section_main_desc_get(void)
{
    return (&g_main_header);
}

signature_descriptor_t* bitstream_parse_section_sig_desc_get(void)
{
    return (&g_signature_descriptor);
}

sdm_return_t parse_descriptors(comp_config_handle_t comp_handle,const main_descriptor_t *main_descriptor, const signature_descriptor_t *signature_descriptor)
{
    uint32_t ret_code = 0;

    ret_code = parse_main_descriptor(comp_handle,main_descriptor);
    if (ret_code != 0)
    {
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
        set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR,ret_code), MAIN_DESC_INVALID);
        return SDM_ERROR;
    }

#ifdef ENABLE_PLATFORM_ATTESTATION
    pa_design_hash_update(main_descriptor, signature_descriptor);
#endif // ENABLE_PLATFORM_ATTESTATION

    return SDM_SUCCESS;
}

/*!
This function is used to validate and authenticate the descriptor based on the main descriptor data and the data in the signature descriptor.
This function is responsible to provide the following levels of validation:

1.- Magic number comparison and type verification

2.- Main descriptor HASH validation

ToDo: add the next level of autentication for the main descriptor here


@param comp_handle comp config driver handler for hash manipulation.
@param p_m_descriptor main descriptor pointer.
@param p_s_descriptor signature descriptor pointer.

@return Returns SDM_SUCCESS if this was an RMA/Engineering descriptor that can be further processed
and SDM_ERROR if this descriptor was not a valid RMA/Engineering descriptor.
 */
sdm_return_t cmf_validate_section_header(comp_config_handle_t comp_handle, const main_descriptor_t *p_m_descriptor, const signature_descriptor_t *p_s_descriptor)
{
    //Check the pointers are valid
    sdm_return_t status = SDM_ERROR;

    hash_mgr_handle_t hash_mgr = comp_config_hash_mgr_handle_get(comp_handle);

    //Local buffer to drain data, we dont look at the data we just need to store it
    uint32_t hash_local_buff[SHA_384_WORD_SIZE] = {0};

    //Magic number validation and type filed verification
    if(!cmf_main_descriptor_valid(p_m_descriptor))
    {
        SDM_TRACE_ERROR(TRACE_BITSTREAM_ERROR, __LINE__);
        set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_CORRUPTION, MAIN_DESC_INVALID), p_m_descriptor->magic_number);
        return SDM_ERROR;
    }

    //[*] Main descriptor HASH checking
    //Compare the main descriptor hash in the signature descriptor
    //At this point we expect that the HASHES for the main and signature
    //descriptor are already queued and ready for comparison using the hash mgr.

    //Adding the block0 hash to the hash manager for comparison
    hash_mgr_add_expected_head(hash_mgr, (uint32_t *)(&(p_s_descriptor->block0_sha)), 1);
    
    //Trigger the hash comparison
    status = hash_mgr_compare(hash_mgr, HASH_SAVE_NONE);
    if (status == SDM_ERROR_MISCOMPARE)
    {
        set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_CORRUPTION, MAIN_DESC_SHA_FAIL), 0);
    }
    else if (status != SDM_SUCCESS)
    {
        SDM_TRACE_ERROR(TRACE_BITSTREAM_ERROR, __LINE__);
        set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BASIC_ERROR), 0);
    }
    //Even if the hash comparison fails we need to clean up
    //Clean up, discard the hash value for the signature descriptor
    hash_mgr_get_calculated(hash_mgr, (uint32_t *)(&hash_local_buff), SHA_384_WORD_SIZE);
    return status;
}


sdm_return_t bitstream_header_processing(comp_config_handle_t comp_config_handle,
                                         const main_descriptor_t *main_descriptor,
                                         const signature_descriptor_t *signature_descriptor)
{
    cmf_efuse_force_pki_slct_t force_pki_slct_efuse_value = CMF_EFUSE_FORCE_PKI_SLCT_NO_USER_PKI;
    sdm_return_t status = SDM_ERROR;
    bool skip_section = false;
    sdm_return_t skip_data_ret = SDM_ERROR;
    bool skip_cmf = false;

    crypto_context_t sdm_auth_context = {0};
    
    SDM_TRACE_INFO(TRACE_CONFIG_STATE_MACHINE_PARSE_SIG_DESC, __LINE__);
	
    if (cmf_config_cvp_type_get() != CVP_NONE)
    {
        // Issue an SDM credit since we need first descriptor block
        // to figure out how many total credits to issue
        cmf_config_cvp_issue_single_credit(comp_config_cnoc_handle_get(comp_config_handle));
		
    }
    bitstream_num_sections_set(signature_descriptor->num_main_sections);
    //
    // If this is a main descriptor then we need to check what type it is.
    //
    if(main_descriptor->magic_number == MAIN_DESCRIPTOR_MAGIC_NUMBER)
    {
        // Bitstream Size Check. The inbuf is 32bits width. When read a data from inbuf, it is always a 4-Bytes aligned. 
        // RTL will always store data in word (not matter in JTAG - single bit, or AVST or QSPI).
        // For the bitstream size, need to make sure the bitstream size that recorded in the descriptor is multiple of 4KBytes
        if (main_descriptor->bitstream_size % BITSTREAM_DATA_BLOCK_SIZE_BYTES != 0 ||
            main_descriptor->bitstream_size < 2 * BITSTREAM_DATA_BLOCK_SIZE_BYTES)
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            SDM_TRACE_INFO(TRACE_GENERIC_INFO, main_descriptor->bitstream_size);
            return SDM_ERROR;
        }

        bitstream_section_bytes_set(main_descriptor->bitstream_size - (BITSTREAM_DATA_BLOCK_SIZE_BYTES<<1));
        bitstream_position_set(BITSTREAM_DATA_BLOCK_SIZE_BYTES << 1);

        // Check if it is not Test FW
        if (!is_test_fw())
        {
            if((main_descriptor->desc_type == DESC_TYPE_IO) ||
                (main_descriptor->desc_type == DESC_TYPE_CORE) ||
                (main_descriptor->desc_type == DESC_TYPE_PR) ||
                (main_descriptor->desc_type == DESC_TYPE_FBRC))
            {
                config_drv_handles_for_authentication(comp_config_handle, &sdm_auth_context);

                //
                // perform authentication of this section
                //
                if(cmf_authenticate(&g_signature_descriptor,
                                    &g_main_header,
                                    CMF_AUTH_KEY_PERMISSIONS__SIGN_IO_CORE_PR,
                                    &sdm_auth_context) != SDM_SUCCESS)
                {
                    SDM_TRACE_ERROR(TRACE_AUTHENTICATION_FAILURE, __LINE__);
                    set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, AUTH_FAIL), 0);
                    return SDM_ERROR;
                }
    #ifdef CMF_AUTH_VAB
                //Upon successful authentication, populate persistent with VAB cancel counters that are
                //used to bring up design. these counter values are NOT cancellable via ccert
                persistent_set_vab_cancel_counters(cmf_authenticate_get_root_hash_id(),
                                                  cmf_authenticate_get_user_pubkey_cancel_mask(),
                                                  cmf_authenticate_get_svn_a_counter(),
                                                  cmf_authenticate_get_svn_b_counter(),
                                                  cmf_authenticate_get_svn_c_counter(),
                                                  cmf_authenticate_get_svn_d_counter(),
                                                  cmf_authenticate_get_pts_counter());
    #endif
                //check if ASIC offloading feature enable is consistent in all sections (IO, CORE, PR)
                //If a section turned on asic offload flag, then all the sections following need to have it enabled
                if (check_comb_feature_enable(main_descriptor->feature_enable_flags, FIXED_FLAG_USER_DESIGN_OFFLOAD) == false)
                {
                    SDM_TRACE_ERROR(TRACE_SECTION_TYPE_NOT_ACCEPT, __LINE__);
                    set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, SECTION_SECURITY_CHECK_FAILED), 0);
                    return SDM_ERROR;
                }
                //Asic offload feature can not enabled on a device in owned state (user pubkey blowned)
                if (is_user_root_pubkey_blown() &&
                   ((main_descriptor->feature_enable_flags & FIXED_FLAG_USER_DESIGN_OFFLOAD) == FIXED_FLAG_USER_DESIGN_OFFLOAD) )
                {
                    SDM_TRACE_ERROR(TRACE_SECTION_TYPE_NOT_ACCEPT, __LINE__);
                    set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, SECTION_SECURITY_CHECK_FAILED), 0);
                    return SDM_ERROR;
                }
            }
            else if( (main_descriptor->desc_type == DESC_TYPE_HPIO) ||
                     (main_descriptor->desc_type == DESC_TYPE_HPS) )
            {
                config_drv_handles_for_authentication(comp_config_handle, &sdm_auth_context);

                //
                // perform authentication of this section
                //
                if(cmf_authenticate(&g_signature_descriptor,
                                    &g_main_header,
                                    CMF_AUTH_KEY_PERMISSIONS__SIGN_HPS,
                                    &sdm_auth_context) != SDM_SUCCESS)
                {
                    SDM_TRACE_ERROR(TRACE_AUTHENTICATION_FAILURE, __LINE__);
                    set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, AUTH_FAIL), 0);
                    return SDM_ERROR;
                }
    #ifdef CMF_AUTH_VAB
                //Upon successful authentication, populate persistent with VAB cancel counters that are
                //used to bring up design. these counter values are NOT cancellable via ccert
                persistent_set_vab_cancel_counters(cmf_authenticate_get_root_hash_id(),
                                                  cmf_authenticate_get_user_pubkey_cancel_mask(),
                                                  cmf_authenticate_get_svn_a_counter(),
                                                  cmf_authenticate_get_svn_b_counter(),
                                                  cmf_authenticate_get_svn_c_counter(),
                                                  cmf_authenticate_get_svn_d_counter(),
                                                  cmf_authenticate_get_pts_counter());
    #endif
            }
            else if ((main_descriptor->desc_type == DESC_TYPE_ASIC) ||
                     (main_descriptor->desc_type == DESC_TYPE_TEST) )
            {
                //
                // Check the FORCE_PKI_SLCT efuse value to determine if we
                // need to authenticate the bitstream with user's public key.
                // TODO: for now if FORCE_PKI_SLCT efuse blown, fail this bitstream (FB451450)
                //       Add authentication later.
                // If user pub key blowned, can not accept ASIC or TEST section
                status = cmf_efuse_get_force_pki_slct(&force_pki_slct_efuse_value);
                if(status != SDM_SUCCESS)
                {
                    SDM_TRACE_ERROR(TRACE_FAIL_EFUSE_FORCE_PKI_SLCT_GET, status);
                    set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, FUSE_RD_FAIL) ,0);
                    return SDM_ERROR;
                }
                SDM_TRACE_INFO(TRACE_INFO_PKI_SLCT_VAL, force_pki_slct_efuse_value);

                //
                // If PKI_FORCE_SLCT efuse blown, then do not play this bitstream
                //
                if(force_pki_slct_efuse_value != CMF_EFUSE_FORCE_PKI_SLCT_NO_USER_PKI)
                {
                    SDM_TRACE_INFO(TRACE_FORCE_PKI_SLCT_EFUSE_BLOWN, __LINE__);
                    set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, SECTION_SECURITY_CHECK_FAILED), 0);
                    return SDM_ERROR;
                }
            }
            else if(main_descriptor->desc_type == DESC_TYPE_CERT)
            {

                const rma_eng_descriptor_t * const p_cert = (const rma_eng_descriptor_t * const)&g_main_header;
                config_drv_handles_for_authentication(comp_config_handle, &sdm_auth_context);
                uint32_t size = BITSTREAM_DATA_BLOCK_SIZE_BYTES * 2;

                if(debug_cert_authenticate(&g_signature_descriptor, p_cert, &sdm_auth_context) == SDM_SUCCESS)
                {
                    if(p_cert->cert_flags & RMA_ENG_CERT_FLAG_ENABLE_HPS_DEBUG)
                    {
                        //
                        // Checks if we should enable HPS debug and does so if it should.
                        // also setup HPS jtag mode pinmux (split or combined)
                        // If HPS is not ready then the config request has been remembered (in debug_cert.c)
                        // and HPS debug enable would be processed during handling of OPERATION_HPS_MPU_READY.
                        //
                        if (g_config_state.status.hps_ready)
                        {
                            if (config_hps_jtag_config() != SDM_SUCCESS)
                            {
                                set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, TRAMP_LOAD_CERT_ERROR), 0);
                                return SDM_ERROR;
                            }
                        }

                        // Certificate bitstream only have main + sig blocks, no need to do compatibility check
                        return SDM_SUCCESS;
                    }
                    if(p_cert->cert_flags & RMA_ENG_CERT_FLAG_ENABLE_FPGA_DEBUG)
                    {
                        //
                        // This was a valid FPGA debug certificate.
                        //
                        SDM_TRACE_ERROR(TRACE_SECTION_TYPE_FPGA_DEBUG, __LINE__);
                    }
                    //Finish CERT section, there should have nothing left in bitstream
                    if (p_cert->cert_size != size)
                    {
                        set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, TRAMP_LOAD_CERT_ERROR), 0);
                        return SDM_ERROR;
                    }
                }
                else
                {
                    SDM_TRACE_ERROR(TRACE_AUTH_INVALID_CERT, __LINE__);
                    set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, TRAMP_LOAD_CERT_ERROR), 0);
                    return SDM_ERROR;
                }
            }

            else
            {
                //Any other section type is not accepted
                SDM_TRACE_ERROR(TRACE_SECTION_TYPE_NOT_ACCEPT, __LINE__);
                set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, SECTION_SECURITY_CHECK_FAILED), 0);
                return SDM_ERROR;
            }
        }
    }
    //
    // This was a boot rom header so we have a CMF descriptor and not a main
    // descriptor.
    //
    else if(main_descriptor->magic_number == ALTR_COMMON_BR_HEADER_MAGIC)
    {

        cmf_br_header_t *p_cmf_br_header = (cmf_br_header_t *)main_descriptor;
 
        bitstream_section_bytes_set(p_cmf_br_header->cmf_descriptor.bitstream_size
                                     - (BITSTREAM_DATA_BLOCK_SIZE_BYTES << 1));
        bitstream_position_set(BITSTREAM_DATA_BLOCK_SIZE_BYTES << 1);
        bitstream_num_sections_set(signature_descriptor->num_main_sections);

        if (sdm_bootrom_main_section_add_update(signature_descriptor, g_persistent_data->rsu_data, p_cmf_br_header->cmf_descriptor.bitstream_size) != SDM_SUCCESS)
        {
            SDM_TRACE_CONFIG(TRACE_ERROR, __LINE__);
            return SDM_ERROR;
        }
        
        // For combined upgrade, clear combined_upgrade_done flag (set back combined_upgrade_done to 0)
        // Previously this was done in init cmf. However since in relative address mode, sdm_bootrom_main_section_add_update()
        // need to know whether we are booting combined app or normal app. Thus, clear the flag here instead
        if(g_persistent_data->rsu_data.flags.enable == 1)
        {
            if (g_persistent_data->rsu_data.flags.combined_upgrade_done == 1)
            {
                rsu_flags_t rsu_flags = {0};
                rsu_flags.enable = 1;
                rsu_flags.combined_upgrade_done = 0;
                persistent_rsu_flags_update(rsu_flags);
                persistent_rsu_cmf_prev_addr_update();
            }
        }

        // HSD:1508596107 - Support non-SEU errors via the SEU error queue. If b8 is set it is enabled
        set_seu_report_non_seu_errors(p_cmf_br_header->cmf_descriptor.cmf_flags);

        if(
            (   // If we get a skip flag then check that the current CMF hash matches the chain
                // loader hash (this is the hash of the CMF that comes after the engineering loader)
                // If it matches then we can skip the engineering loader and let the following code
                // eventually skip the CMF.
                (p_cmf_br_header->cmf_descriptor.cmf_flags & CMF_DESCRIPTOR_CMF_FLAGS_SKIP)
                &&
                (cmf_compatible((const hash_384_t *)signature_descriptor->chain.cmf_block0_hash) == true)
                &&
                (!is_joint_cmf_pka_blown())
            )
            ||
            (  // if CMF descriptor, skip if same CMF; Authenticate and transition to new CMF
                (
                    (g_persistent_data->rsu_data.flags.enable != 1) ||
                    (config_state_get_transition_flag() == false   )
                )
                &&
                (cmf_compatible((const hash_384_t *)signature_descriptor->block0_sha) == true)
                &&
                (!is_joint_cmf_pka_blown())
            )
            ||
            (
                // HPS cold reset case, not reloading the CMF (even if firmware is co-signed)
                (config_state_get_hps_cold_reset_active()) &&
                (cmf_compatible((const hash_384_t *)signature_descriptor->block0_sha) == true)
            )
          )
        {
            SDM_TRACE_CONFIG(TRACE_SKIP_CMF, __LINE__);
            skip_cmf = true;
        }
        //This handles the case where the transition is required.
        //For reconfig scenarios we do not support transition.
        if ((skip_cmf == false) && (config_state_get_reconfig_active()))
        {
            SDM_TRACE_ERROR(TRACE_CMF_TRANSITION_FAIL, __LINE__);
            return SDM_ERROR;
        }
#ifdef ENABLE_PLATFORM_ATTESTATION
        if(pa_exit_event(&skip_cmf) != SDM_SUCCESS)
        {
            return SDM_ERROR;
        }
#endif
        if (skip_cmf)
        {
            //HSD 1707257621: If 1st bitstream is an fpga first image, not allowed to reconfig
            //from HPS.
            if((!action_if_get_hps_first()) &&
                (config_state_get_reconfig_active()) &&
                (g_config_state.mbox_config_select == MBOX_CONFIG_SOURCE_HPS))
            {
                SDM_TRACE_ERROR(TRACE_HPS_ERROR_FPGA_FIRST, __LINE__);
                return SDM_ERROR;
            }

            uint32_t size = p_cmf_br_header->cmf_descriptor.bitstream_size;

            // Calculate the remaining bytes from the boot rom header.
            // ssbl size + offset - the 8K header that we have already read.
            size = size - (SDM_INBUF_PACKET_BYTE_SIZE << 1);
            if (bitstream_source_get() != BITSTREAM_SOURCE_QSPI)
            {
                skip_data_ret = comp_config_skip_data(comp_config_handle, size);
            }
            else
            {
                skip_data_ret = SDM_SUCCESS;
            }

            if (skip_data_ret == SDM_SUCCESS)
            {
                if(bitstream_advance(size) != SDM_SUCCESS)
                {
                    set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, BASIC_ERROR), 0);
                    SDM_TRACE_ERROR(TRACE_ERROR, __LINE__); 
                    skip_data_ret = SDM_ERROR;              
                }
                bitstream_num_sections_dec();
                bitstream_source_point_to_main_section();
            }
            else if (skip_data_ret == SDM_ERROR_ABORT)
            {
                set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BITSTREAM_INTERRUPTED), 0);
            }
            else
            {
                set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, SKIP_DATA_PREBUF_ERR), 0);
            }
#ifdef HAL_FALCONMESA
#ifdef CMF_AUTH_VAB
            if (skip_data_ret == SDM_SUCCESS)
            {
                // clear any previous counter preauthorizations
                vab_counter_clear_preauth();
                // clear all PR owner preauthorizations
                vab_pr_owner_clear_authorization();
            }
#endif
#endif
            return (skip_data_ret);
        }
        //
        // Not skipping so authenticate the new CMF before loading.
        //
        else
        {
#ifdef ENABLE_TEST_DEBUG
            test_printf("This is trampoline\n");
#endif
            // Check that the new CMF type matches the previous CMF type
            if(cmf_compatible_type(p_cmf_br_header->cmf_descriptor.cmf_flags) == false)
            {
                set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BS_INCOMPATIBLE), 0);
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                return SDM_ERROR;
            }

            //This is the new CMF, check if we are in reconfig stage.
            //If we need to protect any part, then can not transition to new CMF. Have to error. 
            if (config_state_get_reconfig_active())
            {
                set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, BASIC_ERROR), 0);
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                return SDM_ERROR;
            }
            else
            {
                SDM_TRACE_INFO(TRACE_NEW_CMF, __LINE__);

                config_drv_handles_for_authentication(comp_config_handle, &sdm_auth_context);

                // 
                // perform authentication of the cmf descriptor for this new cmf image.
                //
                if(cmf_authenticate(&g_signature_descriptor,
                                    &g_main_header,
                                    CMF_AUTH_KEY_PERMISSIONS__SIGN_CODE,
                                    &sdm_auth_context) != SDM_SUCCESS)
                {
                    SDM_TRACE_ERROR(TRACE_AUTHENTICATION_FAILURE, __LINE__);
                    set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, AUTH_FAIL), 0);
                    return SDM_ERROR;
                }
                else
                {
                    // Check if the physical_jtag_id of the new cmf desc matches that of the JTAG ID from the device fuse
                    // We are using the JTAG ID mask of the incoming CMF.
                    if(((p_cmf_br_header->cmf_descriptor.physical_jtag_id ^ cmf_efuse_get_jtag_id()) &
                        p_cmf_br_header->br.jtag.idcode_mask) != 0)
                    {
                        SDM_TRACE_ERROR(TRACE_BAD_JTAG_ID, p_cmf_br_header->cmf_descriptor.physical_jtag_id);
                        set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, CMF_DESC_BAD_JTAG_ID), 0);
                        return SDM_ERROR;
                    }

                    // Transition to new CMF firmware.  Shall not return if transition happens
                    return(state_cmf_transition(main_descriptor, signature_descriptor));
                }
            }
        }
    }

    //
    // Basic data structure hash, design hash, version compatible checks on the bitstream header.
    // Even if the section is going to be skipped
    //
    if(cmf_compatible_bitstream_check(main_descriptor) != SDM_SUCCESS)
    {
        set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BS_INCOMPATIBLE), 0);
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
        return SDM_ERROR;
    }

    //check if we need to skip the current section
    //HPS cold reset case, protect FPGA and any IO
    if ((action_if_get_protect_hpio() && action_if_get_protect_fpga()) &&
        ((g_main_header.desc_type == DESC_TYPE_IO) ||
         (g_main_header.desc_type == DESC_TYPE_HPIO) ||
         (g_main_header.desc_type == DESC_TYPE_FBRC)))
    {
        skip_section = true;

        if (g_main_header.desc_type == DESC_TYPE_FBRC)
        {
            // Update HPS flags since FBRC main descriptor is not processed during HPS cold reset flow
            config_hps_set_flags(main_descriptor->hps_flags, main_descriptor->hps_flags_2);
        }
    }
    // HPS configuration of FPGA, protect HPS and HPIO only
    else if ((action_if_get_protect_hpio() && !action_if_get_protect_fpga() &&
              action_if_get_protect_hps()) &&
             (g_main_header.desc_type == DESC_TYPE_HPIO))
    {
        skip_section = true;
    }
    else if ((action_if_get_protect_fpga()) &&
             (g_main_header.desc_type == DESC_TYPE_CORE))

    {
        skip_section = true;
    }
    else if ((action_if_get_protect_hps()) &&
             (g_main_header.desc_type == DESC_TYPE_HPS))
    {
        skip_section = true;
    }

    if(skip_section == true)
    {
        uint32_t size = bitstream_section_bytes_get();
        // if config source is QSPI, then directly update the qspi_src_addr.
        if (bitstream_source_get() == BITSTREAM_SOURCE_QSPI)
        {
            uint32_t qspi_addr = config_dma_get_flash_addr();
            config_dma_flash_add_update(qspi_addr + size);
            SDM_TRACE_INFO(TRACE_GENERIC_INFO, __LINE__);
        }

#if 0 // Ignore SDMMC support
#ifdef INCLUDE_SDMMC
        else if (get_crypto_sdmmc_config_enabled() == true)
        {
            uint32_t sdmmc_addr = get_sdmmc_src_addr();
            set_sdmmc_src_addr(sdmmc_addr + size);
        }
#endif
#endif 

        else //Other cases, skip data sections by request PreBuff to SINK
        {
            skip_data_ret = comp_config_skip_data(comp_config_handle, size);
            if(skip_data_ret == SDM_ERROR_ABORT)
            {
                //goto_bitstream_interrupted();
                set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BITSTREAM_INTERRUPTED), 0);
                SDM_TRACE_ERROR(TRACE_BITSTREAM_INTERRUPTED, __LINE__);
                return skip_data_ret;
            }

            else if (skip_data_ret != SDM_SUCCESS)
            {
                set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, SKIP_DATA_PREBUF_ERR), 0);
                SDM_TRACE_ERROR(TRACE_SKIP_SECTION, __LINE__);
                return skip_data_ret;
            }
        }
        SDM_TRACE_INFO(TRACE_SKIP_SECTION, __LINE__);
        SDM_TRACE_INFO(TRACE_SKIP_SECTION, main_descriptor->desc_type);
        bitstream_num_sections_dec();
        //
        //update bitstream position
        //
        if(bitstream_advance(size) != SDM_SUCCESS)
        {
            set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, BASIC_ERROR), 0);
            SDM_TRACE_ERROR(TRACE_SKIP_SECTION, __LINE__);
            return SDM_ERROR;
        }
    }
    
    return SDM_SUCCESS;
}

/*!
 * @brief  This function is called to authentcate a bitstream section for HPS VAB PreAuthentication
 *
 * @param comp_config_handle is valid comp_config_handle
 * @param main_descriptor is a pointer to the main descriptor
 * @param signature_descriptor is a pointer to the main descriptor
 *
 * @return Returns SDM_SUCCESS if authentcation succeeds
 */
sdm_return_t bitstream_header_authenticate(comp_config_handle_t comp_config_handle,
                                         const main_descriptor_t *main_descriptor,
                                         const signature_descriptor_t *signature_descriptor)
{
    uint32_t permissions = 0;    
    crypto_context_t sdm_auth_context = {0};
    
    SDM_TRACE_INFO(TRACE_CONFIG_STATE_MACHINE_PARSE_SIG_DESC, __LINE__);
	
    if(main_descriptor->magic_number == MAIN_DESCRIPTOR_MAGIC_NUMBER)
    {
        if((main_descriptor->desc_type == DESC_TYPE_IO) ||
            (main_descriptor->desc_type == DESC_TYPE_CORE) ||
            (main_descriptor->desc_type == DESC_TYPE_PR) ||
            (main_descriptor->desc_type == DESC_TYPE_FBRC))
        {
            permissions = CMF_AUTH_KEY_PERMISSIONS__SIGN_IO_CORE_PR;
        }
        else if( (main_descriptor->desc_type == DESC_TYPE_HPIO) ||
                 (main_descriptor->desc_type == DESC_TYPE_HPS) )
        {
            permissions = CMF_AUTH_KEY_PERMISSIONS__SIGN_HPS;
        }
        else if(main_descriptor->desc_type == DESC_TYPE_CERT)
        {

            const rma_eng_descriptor_t * const p_cert = (const rma_eng_descriptor_t * const)main_descriptor;
            config_drv_handles_for_authentication(comp_config_handle, &sdm_auth_context);
            if(debug_cert_authenticate(signature_descriptor, p_cert, &sdm_auth_context) == SDM_SUCCESS)
            {
                return SDM_SUCCESS;
            }
            else
            {
                SDM_TRACE_ERROR(TRACE_AUTH_INVALID_CERT, __LINE__);
                return SDM_ERROR;
            }
        }
        else
        {
            //Any other section type is not accepted
            SDM_TRACE_ERROR(TRACE_SECTION_TYPE_NOT_ACCEPT, __LINE__);
            return SDM_ERROR;
        }        
    }
    else if(main_descriptor->magic_number == ALTR_COMMON_BR_HEADER_MAGIC)
    {
        permissions = CMF_AUTH_KEY_PERMISSIONS__SIGN_CODE;
    }
    else
    {       
        //Any other section type is not accepted
        SDM_TRACE_ERROR(TRACE_SECTION_TYPE_NOT_ACCEPT, __LINE__);
        return SDM_ERROR;
    }
   
    config_drv_handles_for_authentication(comp_config_handle, &sdm_auth_context);
    
    if(cmf_authenticate(signature_descriptor,
                        main_descriptor,
                        permissions,
                        &sdm_auth_context) != SDM_SUCCESS)
    {
        SDM_TRACE_ERROR(TRACE_AUTHENTICATION_FAILURE, __LINE__);
        return SDM_ERROR;
    }

    return SDM_SUCCESS;   
}

/*!
This function is called to verify that the main descriptor is valid.

@param main_descriptor is a pointer to the main descriptor that was passed in
via the bit stream.

@return Returns zero if the main descriptor was valid and non-zero if
there was a problem with the main descriptor.
 */
static uint32_t parse_main_descriptor(comp_config_handle_t comp_handle, const main_descriptor_t *main_descriptor)
{
    uint32_t offset;
    sdm_return_t status;
    crypto_context_t crypto_ctx = {0};

    bool sec_option_enabled = false;

    if(main_descriptor->section_mode_flags.hash_size == SECTION_MODE_FLAGS_HASH_256)
    {
        if(comp_config_sha_size_set(comp_handle, SHA_256_WORD_SIZE) != SDM_SUCCESS)
        {
            return (SHA_SETUP_FAIL);
        }
    }
    else if(main_descriptor->section_mode_flags.hash_size == SECTION_MODE_FLAGS_HASH_384)
    {
        if(comp_config_sha_size_set(comp_handle, SHA_384_WORD_SIZE) != SDM_SUCCESS)
        {
            return (SHA_SETUP_FAIL);
        }
    }
    else
    {
        return (MAIN_DESC_INVALID);
    }

    //
    // Check if the Version number is non zero. Reject if the version number is not equal to 0
    //
    if((main_descriptor->public_version.build != 0) ||
       (main_descriptor->public_version.major != 0) ||
       (main_descriptor->public_version.minor != 0))
    {
        return(MAIN_DESC_VERSION_INVALID);
    }

#ifdef HAL_NADDER
    // AS Handling configuration will fail if NO_SGX is fused and NON_AS_DEVICE=0 in the bitstream
    // NOTE: Applies only for ND where customers might get non-SFE devices
    if (SDM_SUCCESS != cmf_as_compatibility_check(main_descriptor->section_mode_flags))
    {
        return(MAIN_DESC_AS_DEVICE_NO_SGX_ERROR);
    }
#endif

    if (!is_test_fw())
    {
        if(main_descriptor->section_mode_flags.device_type != DEVICE_TYPE)
        {
            return(MAIN_DESC_DEVICE_TYPE_INVALID);
        }
    }

    // For incoming CORE descriptors, keep a copy of the design hash in NSP RAM
    if ((main_descriptor->desc_type == DESC_TYPE_CORE) ||
	    (main_descriptor->desc_type == DESC_TYPE_FBRC))
    {
        if(cmf_designhash_set(main_descriptor->design_hash, sizeof(main_descriptor->design_hash)) != SDM_SUCCESS)
        {
            return(MAIN_DESC_DESIGN_HASH_ERR);
        }
    }

#ifdef ENABLE_PLATFORM_ATTESTATION
    if((main_descriptor->desc_type == DESC_TYPE_IO) ||
        (main_descriptor->desc_type == DESC_TYPE_HPIO) ||
        (main_descriptor->desc_type == DESC_TYPE_FBRC))
    {
            // Keep a copy of the attestation table which is used for the alias certificate
            if(main_descriptor->offset_attestation_table != 0 && (pa_attestation_table_set((char *)(main_descriptor) + main_descriptor->offset_attestation_table) != SDM_SUCCESS))
            {
                return(BASIC_ERROR);
            }

            // Keep a copy of the 'use AliasL1' flag
            pa_bitstream_flag_use_aliasl1_set((main_descriptor->feature_enable_flags & PA_MAIN_DESCRIPTOR_FEATURE_FLAGS_USE_ALIASL1) != 0);

            // AliasL1 flag and fuse are mutually exclusive, if 'use AliasL1' and 'disable AliasL1'
            // are both set, the section should fail to load.
            if(pa_bitstream_flag_use_aliasl1_get() && pa_efuse_disable_aliasl1_get())
            {
                return(BASIC_ERROR);
            }
    }
#endif

#if defined(ENABLE_AFRL_ATTESTATION) || defined(ENABLE_PLATFORM_ATTESTATION)
    // Glen Pass Project FW Spec, section 8.4.2:
    // Any section (IO, Core, HPS or HPIO) in user bitstream has the attestation enable flag set,
    // then firmware shall enable the attestation request support.
    if((main_descriptor->desc_type == DESC_TYPE_IO) ||
        (main_descriptor->desc_type == DESC_TYPE_CORE) ||
        (main_descriptor->desc_type == DESC_TYPE_HPS) ||
        (main_descriptor->desc_type == DESC_TYPE_HPIO))
    {
        if( (main_descriptor->feature_enable_flags & PA_MAIN_DESCRIPTOR_FEATURE_FLAGS_ND_ATTESTATION) != 0 )
        {
            sdm_attest_enable();
        }
    }
#endif

    //
    // Update the JTAG user code from the bitstream so that we can return it later if the
    // host requests it.
    //
    alt_sdm_jtag_usercode_set(main_descriptor->usercode);

    if(hal_has_hps())
    {
        //check HPS related bitstream variables and flags
        if((main_descriptor->desc_type == DESC_TYPE_IO) ||
            (main_descriptor->desc_type == DESC_TYPE_HPIO) ||
            (main_descriptor->desc_type == DESC_TYPE_FBRC))
        {
            check_hps_bitstream_variable(main_descriptor->variable_value);
            config_hps_set_flags(main_descriptor->hps_flags, main_descriptor->hps_flags_2);
        }

        // DDR hash is part of HPS section
        if(main_descriptor->desc_type == DESC_TYPE_HPS)
        {
            // Read DDR hash from slot provided table and save it into persistent RAM if it is POR
            // Or compare it with the one stored in persistent RAM if it is not POR/nConfig/JtagConfig
            if (config_hps_check_ddr_retention(main_descriptor) != SDM_SUCCESS)
            {
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                return(MAIN_DESC_READ_DDR_HASH_FAIL);
            }
        }
    }

    //
    //Process IO tables and config PLL only for initial configuration. For HPS cold reset where
    //IO is protected, no need to processs IO tables again. Also applied to HPS_first configuration
    //FPGA phase (2nd phase)
    if(((main_descriptor->desc_type == DESC_TYPE_IO) && (!action_if_get_protect_hpio()) && (!action_if_get_hps_first())) ||
       ((main_descriptor->desc_type == DESC_TYPE_FBRC) && (!action_if_get_protect_hpio()) && (!action_if_get_hps_first())) ||
       ((main_descriptor->desc_type == DESC_TYPE_HPIO) && (action_if_get_hps_first())))
    {
        // check osc_clk_1 field, 3 modes possible
        // 1.Configuration system and SDM CPU run from PLL driven from osc_clk_1 (EXTERNAL)
        // 2.Configuration system and SDM CPU run from internal oscillator (INTERNAL)
        // 3.Configuration system (except CPU) runs from PLL, CPU runs from internal oscillator (SECURE EXTERNAL)

        if(config_clock_open() != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return (MAIN_DESC_EXT_REF_CLK_ERR);
        }

        uint32_t msel_used = persistent_get_msel_used();
        bool qspi_update_clk_en = false;
        if ((msel_used == ALTR_CMF_NSP_MSEL_QSPI_NORM) || (msel_used == ALTR_CMF_NSP_MSEL_QSPI_FAST))
        {
            qspi_update_clk_en= true;
        }

        if (config_clock_setup_clocks(OSC_CLK_1_INTERNAL_OSC_GET(main_descriptor->osc_clk_1),
                                       OSC_CLK_1_EXTERNAL_PIN_FREQ_GET(main_descriptor->osc_clk_1),
                                       main_descriptor->as_clk_desired_rate, qspi_update_clk_en) != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return (MAIN_DESC_EXT_REF_CLK_ERR);
        }

        // Initialize the Security Options module
        if(cmf_sec_options_init(main_descriptor) != SDM_SUCCESS)
        {
            return(MAIN_DESC_SEC_OPTIONS_INIT_FAIL);  
        }

        // Apply the Secure Clock Security Option
        if((cmf_sec_options_get_option_status(SEC_OPTIONS_SECURE_CLOCK,
                                              &sec_option_enabled) != SDM_SUCCESS) ||
                                              (sec_option_enabled == true))
        {
            // If Secure Clock Option is enabled (or was not able to be determined),
            // do not allow external clock to drive NSP CPU
            if(clkmgr_get_mode() == CLKMGR_MODE_PLL)
            {
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                return(MAIN_DESC_EXT_CLOCK_MODE_DISALLOWED);
            }
        }
        if(cmf_sec_options_get_option_status(SEC_OPTIONS_JTAG_DISABLE,
                                            &sec_option_enabled) != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);            
            return(SDM_ERROR);
        }

        if(sec_option_enabled)
        {
            // disable all jtag interrupts
            jtag_disable_main_int(true);
        }        

        // save SEU_AUTO_CORRECT setting from bitstream
        set_seu_auto_correct(main_descriptor->other_flags);
        // save Fault Inject setting from bitstream
        set_seu_error_inject(main_descriptor->feature_enable_flags);

        status = power_table_init(main_descriptor);
        if(status == SDM_ERROR_FUNCTION_NOT_SUPPORTED)
        {
            SDM_TRACE_INFO(TRACE_POWER_TABLE_PMF_NOT_SUPPORTED, __LINE__);
            return  (MAIN_DESC_PMF_NOT_SUPPORTED);
        }
        else if (status != SDM_SUCCESS)
        {
            SDM_TRACE_INFO(TRACE_POWER_TABLE_ERROR, __LINE__);
            return SDM_ERROR;
        }

        // For HPS_first configuration, we already get a valid pin table from HPIO section,
        // ignore the current one here
        if (pin_table_valid() && action_if_get_hps_first() && (main_descriptor->desc_type == DESC_TYPE_IO))
        {
            SDM_TRACE_INFO(TRACE_PIN_TABLE_SKIPPED, __LINE__);
        }
        else if (main_descriptor->offset_pin_table != 0)
        {
            //
            // Pin table must fit in remainder area of the main descriptor.
            // Checks that there is room at the end and that the offset is
            // past the normal main header offset information.
            //
            if((main_descriptor->offset_pin_table >
                sizeof(main_descriptor_t) - sizeof(pin_table_t) - sizeof(uint32_t)) ||
                (main_descriptor->offset_pin_table < offsetof(main_descriptor_t, other)))
            {
                SDM_TRACE_INFO(TRACE_PIN_TABLE_ERROR, __LINE__);
                return (MAIN_DESC_PIN_TBL_OFFSET_ERR);
            }

            offset = main_descriptor->offset_pin_table -
                     offsetof(main_descriptor_t, other);

            if(pin_table_init((pin_table_t *)&main_descriptor->other[offset>>2]) != 0)
            {
                SDM_TRACE_INFO(TRACE_PIN_TABLE_ERROR, __LINE__);
                return (MAIN_DESC_PIN_TBL_INVALID);
            }
#if 0
// EDW: Ignoring for now
#if NO_FILTER
#if defined(FAKE_NHPSRST_TOGGLE) && defined(FORCE_TOGGLE_GPIO)
            //Quartus may not have pin functions added, init SDMIO_12 pin
            gpio_pin_init(12);
#endif
#endif
#endif
        }
        else
        {
            SDM_TRACE_INFO(TRACE_PIN_TABLE_ERROR, __LINE__);
            return (MAIN_DESC_NO_PIN_TBL);
        }
#if 0

#if NO_FILTER
        // TODO to support other flash types (sdmmc, nand etc) need to check what is config type (sdmmc vs qspi etc)
        // For flash table not supported in bitstream so leave commented out
        if(main_descriptor->offset_flash_table != 0)
        {
            //
            // Flash table must fit in remainder area of the main descriptor.
            // Checks that there is room at the end and that the offset is
            // past the normal main header information.
            //
            if((main_descriptor->offset_flash_table >
                sizeof(main_descriptor_t) - sizeof(qspi_table_t) - sizeof(uint32_t)) ||
               (main_descriptor->offset_flash_table < offsetof(main_descriptor_t, other)))
            {
//                DPRINTF(DPRINTF_ERROR, "ERROR bad offset to flash table %d.\n",
//                        main_descriptor->offset_flash_table);
//                DPRINTF(DPRINTF_ERROR, "sizeof %0x %0x\n", sizeof(qspi_table_t),
//                        offsetof(main_descriptor_t, other));
            }
            else
            {
                offset = main_descriptor->offset_flash_table -
                         offsetof(main_descriptor_t, other);

                if(qspi_table_init((const qspi_table_t *)&main_descriptor->other[offset>>2]) != 0)
                {
//                    DPRINTF(DPRINTF_ERROR, "ERROR qspi_table_init failed.\n");
                    // TODO dont set error state for now until we debug this
                    //g_crypto.state_function = state_error;
                    //alt_sdm_cfg_status_set_state(MBOX_CFGSTAT_STATE_ERROR_INVALID);
                    SDM_trace(CC_ERROR, __LINE__);
                }
            }
        }
#endif
#endif
//anti-tamper code here
#ifdef ENABLE_ANTI_TAMPER
    // For HPS_first configuration, we already get a valid anti-tamper table from HPIO section,
    // ignore the current one here
    if (anti_tamper_table_valid() && action_if_get_hps_first() && (main_descriptor->desc_type == DESC_TYPE_IO))
    {
        //Skipt parsing
        SDM_TRACE_INFO(TRACE_ANTI_TAMPER_TABLE_SKIPPED, __LINE__);
    } else {
        //We process the table
        SDM_TRACE_INFO(TRACE_PARSING_ANTI_TAMPER_TABLE, __LINE__);
        //Parse the descriptor
        if (anti_tamper_table_init(main_descriptor) !=  SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ANTI_TAMPER_PARSE_ERROR, __LINE__);
            return(MAIN_DESC_ANTI_TAMPER_TBL_INVALID);
        }
	    if (anti_tamper_detection_init() != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ANTI_TAMPER_INIT_ERROR, __LINE__);
            return(MAIN_DESC_ANTI_TAMPER_DET_INIT_FAIL);
        }
    }
#else
    //need to make sure anti tamper is disabled in descriptor
    if (main_descriptor->desc_type == DESC_TYPE_IO || main_descriptor->desc_type == DESC_TYPE_HPIO)
    {
        //Just need to make sure the global anti tamper is not enabled
        if (main_descriptor->global_anti_tamper_cfg != 0)
        {
            SDM_TRACE_ERROR(TRACE_ANTI_TAMPER_NOT_SUPPORTED_ERROR, __LINE__);
            return (MAIN_DESC_ANTI_TAMPER_NOT_SUPPORTED);
        }
    }
#endif


        // For HPS_first configuration, we already get a valid user enabling fuse cancellation table from HPIO section,
        // ignore the current one here
        if ((efuse_policy_user_cancellation_fuse_table_valid() == SDM_SUCCESS) &&
            action_if_get_hps_first() &&
            (main_descriptor->desc_type == DESC_TYPE_IO))
        {
            //Skipt parsing
            SDM_TRACE_INFO(TRACE_CMF_PARSING_EN_FUSE_USR_CANCELL_TABLE_SKIPPED, __LINE__);
        } else {
            //We process the table
            SDM_TRACE_INFO(TRACE_CMF_PARSING_EN_FUSE_USR_CANCELL_TABLE, __LINE__);
            //Parse the descriptor
            efuse_policy_user_cancellation_fuse_table_init(main_descriptor->permitted_usr_cancellation_fuses);
        }
#if 0        
        //check clock change for current IO sector, and perform clock change include
        //PLL programming if needed. If PLL can not lock, transition to error state
        //SDM_trace(PLL_CHANGE_FREQ_START, __LINE__);

        if(get_crypto_qspi_config_enabled())
        {
            //Disable Qspi before you make any PLL changes
            cmf_qspi_disable_qspi_controller();
            //Clock gate the Qspi trunk before making any changes
            cmf_qspi_clockgate_controller();
        }

#endif

        //This function will change the PLL and all the mux settings
        if(config_clock_update(CLOCK_EVENT_CNOC_FULL_SPEED) != SDM_SUCCESS)
        {
            return(MAIN_DESC_CONFIG_CLK_PLL_FAILED);
        }

        //We dont need to adjust clks anymore
        config_clock_close();
        // qspi ref clock setup using this new PLL setting will be done when bitstream_source open
    }

    if(main_descriptor->desc_type == DESC_TYPE_CORE ||
       main_descriptor->desc_type == DESC_TYPE_PR)
    {
        // EDW: Will need to port this function over (handle slot table)
        if(SDM_SUCCESS != check_pofID(main_descriptor))
        {
            /* This PR cannot be loaded because it doesn't fit a slot
               in the core or in another PR */
            //SDM_trace(CC_ERROR, __LINE__);
            return(MAIN_DESC_POF_ID_FAILED);
        }
    }

    // section compatibility check
    if (check_section_compat(main_descriptor) != SDM_SUCCESS)
    {
        //SDM_trace(CC_ERROR, __LINE__);
        return(SECTION_COMPAT_CHECK_ERR);
    }


    // Check if encryption is enabled for this main section
    // EDW: Comment encryption/scramble for now
    status = cmf_config_aes_check_encryption_enabled(comp_handle, main_descriptor);
    if(status != SDM_SUCCESS)
    {
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
        return MAIN_DESC_AES_ECRYPT_CHECK_FAIL;
    }

    //Only check for crete/uib if pgm has it defined. DM currently doesn't
    //support this feature. 
    if((main_descriptor->compat_mask_0) || (main_descriptor->compat_mask_1) || (main_descriptor->compat_mask_2) || (main_descriptor->compat_mask_3))
    {
        //For ND Compat ID check from BANK 2, row 24-26 if they match the descriptor data
        //For FM Compat ID check from BANK 2, row 40-43 if they match the descriptor data
        //so the accessor code is generic for both FM and ND
        uint32_t compID_values[ALTR_CMF_EFUSE_CRETE_FUSE_TOTAL_ROWS] = {0};
        uint32_t efuse_row = 0;
        struct comp_idmask {
            uint32_t id;
            uint32_t mask;
        };
        struct comp_idmask *comp_idmask = (struct comp_idmask *)&main_descriptor->compat_id_0;

        if(cmf_efuse_get_crete_dd(&compID_values[0], ALTR_CMF_EFUSE_CRETE_FUSE_TOTAL_ROWS) != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return(FUSE_RD_FAIL);
        }

        if(!is_test_fw())
        {
            //In main descriptor there are four rows, of which have compat ID value 0, compat ID value 1, compat ID value 2 and compat ID value 3
            //defined respectively which should match the fuse values from bank 2 read row by row.
            for (efuse_row = 0; efuse_row < ALTR_CMF_EFUSE_CRETE_FUSE_TOTAL_ROWS; efuse_row++)
            {

                if((comp_idmask[efuse_row].id  & comp_idmask[efuse_row].mask)!= (compID_values[efuse_row] & comp_idmask[efuse_row].mask))
                {
#ifdef ENABLE_TEST_DEBUG

                    test_printf("Row:%08X CP_ID :%08X vs %08X (%08X)\n", efuse_row, comp_idmask[efuse_row].id , compID_values[efuse_row], comp_idmask[efuse_row].mask);
#endif

         // Some variants of NADDER do not have COMPAT_ID fuse values set correctly
         // Per the HSD:18014972792, supressing this test when running on Nadder based products

         // Emulator does not have tile present
#if  !( defined(EMULATOR) || defined(HAL_NADDER) )

                SDM_TRACE_ERROR(TRACE_ERROR, efuse_row);
                SDM_TRACE_ERROR(TRACE_ERROR, compID_values[efuse_row]);
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                return(MAIN_DESC_COMPAT_ID_MATCH_ERR);
#endif
                }
            }
        }
    }

#if 0
#if NO_FILTER
    if(main_descriptor->desc_type == DESC_TYPE_IO ||
       main_descriptor->desc_type == DESC_TYPE_PR ||
       main_descriptor->desc_type == DESC_TYPE_CORE)
    {
        uint16_t offset_slots_table = 0;
        uint16_t num_slots = 0;
        if(main_descriptor->offset_slots_provided_table != 0)
       {
            offset_slots_table = main_descriptor->offset_slots_provided_table;
            num_slots = main_descriptor->num_slots_provided;
        }
        else if((main_descriptor->offset_slots_used_table != 0) &&
               (main_descriptor->desc_type == DESC_TYPE_PR || main_descriptor->desc_type == DESC_TYPE_CORE))
        {
            offset_slots_table = main_descriptor->offset_slots_used_table;
            num_slots = main_descriptor->num_slots_used;
        }
        if(!num_slots)
        {
           // 11/06/2018: We have hammer tests failing due to all these checks. Disabling this for now until we fix this properly
         ////SDM_trace(CC_ERROR, __LINE__);
         ////return ((main_descriptor->offset_slots_provided_table != 0) ? MAIN_DESC_SP_TBL_INVALID : MAIN_DESC_SU_TBL_INVALID);
        }
        // Insure that the table is correctly located in offset
        if((offset_slots_table > sizeof(main_descriptor_t) -sizeof(slot_table_t) -sizeof(uint32_t)) ||
           (offset_slots_table < offsetof(main_descriptor_t, other)))
        {
           // 11/06/2018: We have hammer tests failing due to all these checks. Disabling this for now until we fix this properly
         ////SDM_trace(CC_SLOT_BAD_OFFSET, __LINE__);
         //return((main_descriptor->offset_slots_provided_table != 0) ? MAIN_DESC_SP_TBL_OFFSET_ERR : MAIN_DESC_SU_TBL_OFFSET_ERR);
        }
    }
#endif

#endif // #if 0

    // Create a new crypto context
    if(SDM_SUCCESS != crypto_context_create(&crypto_ctx,
                                             comp_config_inbuf_handle_get(comp_handle),
                                             comp_config_dma_handle_get(comp_handle),
                                             comp_config_sha_handle_get(comp_handle),
                                             comp_config_pkc_handle_get(comp_handle)))
    {
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
        return SDM_ERROR;
    }

    //perform the check if it is not TEST cmf.
    if(!is_test_fw())
    {
        //
        // Bitstream modification prevention feature to give us high confidence that
        // the bitstream has not been tampered with.
        //
        status = bitstream_mod_prevention_check(&crypto_ctx, main_descriptor);
        if(status != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_KEYED_HASH_ERROR, __LINE__);
            return(MAIN_DESC_KEYED_HASH_ERROR);
        }
    }

    // Check if scrambling is enabled for this main section. This should only be called after encryption check is done.
    status = config_cnoc_scramble_check_scrambler_enabled(&crypto_ctx, main_descriptor);
    if(status != SDM_SUCCESS)
    {
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
        //return(MAIN_DESC_SCRAMBLE_RATIO_CHECK_FAIL);
        return SDM_ERROR;
    }

#if 0
    //Save feature enable bits for offloading and others.
    set_comb_feature_enable(main_descriptor->feature_enable_flags);
#endif

    return SDM_SUCCESS;
}

/*!
 This is a transitory state in the hand off to the decompression stub which loads the
 compressed trampoline. If this function returns then there was an error otherwise the
 decompression stub has control of the system.

 @return SDM_ERROR if something goes wrong.
 */
static sdm_return_t state_cmf_transition(const main_descriptor_t *p_main_header, const signature_descriptor_t *p_signature_descriptor)
{
    cmf_br_header_t *p_cmf_br_header = NULL;
    uint32_t trampoline_size = 0;

    p_cmf_br_header = (cmf_br_header_t *)p_main_header;
    trampoline_size = p_cmf_br_header->cmf_descriptor.trampoline_size_bytes;

    if (trampoline_size == 0)
    {
        SDM_TRACE_ERROR(TRACE_CMF_TRANSITION_FAIL, __LINE__);
        return SDM_ERROR;        
    }

    if (cmf_reload_handle_init() == SDM_ERROR_BAD_HANDLE)
    {
        SDM_TRACE_ERROR(TRACE_CMF_TRANSITION_FAIL, __LINE__);
        return SDM_ERROR;
    }

    if(cmf_reload_trampoline_init(trampoline_size) == SDM_SUCCESS)
    {
        if(cmf_reload_trampoline_load(p_cmf_br_header->cmf_descriptor.trampoline_sha_384) == SDM_SUCCESS)
        {
#ifdef HAL_FALCONMESA
            //Need to copy trampoline related data structures in case we're transitioning from 20.x into 19.x
            if( create_19x_handoff_data() )
            {
                //CMFD and signatures were moved to new memory locations, adjust local pointers accordingly.
                p_main_header = (const main_descriptor_t *)MAIN_HEADER_19X_DEST_ADDR;
                p_signature_descriptor = (const signature_descriptor_t *)SIG_DESCRIPTOR_19X_DEST_ADDR;
                
                //SDM_trace(TRAMP_LOAD_19X, 0);
            }
#endif
#if 0
#if defined(PLATFORM_FALCONMESA) && defined(INCLUDE_SDMMC)
            if(g_persistent_data->msel_used == ALTR_CMF_NSP_MSEL_SDMMC)
            {
                //PRINTF("%s %08x do something\n", __func__, __LINE__);
            }
#endif
#endif
            // Point of no return
            // Differentiate between FM and ND, in ND scenario we will load the tramp
            // DC at 0x13A000 relocate it to 0x138000 and then jump to its execution
            // address at 0x138050.
#ifdef PLATFORM_STRATIX10
            uint32_t *dc_load_addr = (uint32_t *)DECOMPRESSION_STUB_LOAD_ADDR_RELOCATE;
#else
            uint32_t *dc_load_addr = (uint32_t *)DECOMPRESSION_STUB_LOAD_ADDR;
#endif
            cmf_reload_decomp_stub_load_and_run(
                dc_load_addr, DECOMPRESSION_STUB_EXE_ADDR, 
                (uint32_t)p_main_header, CMF_PARAM_COLD_RESET, (uint32_t)p_signature_descriptor
            );
        }
    }

    //
    // No good reason to get here other than an error.
    //
    set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, CMF_TRANSITION_FAIL), 0);
    SDM_TRACE_ERROR(TRACE_CMF_TRANSITION_FAIL, __LINE__);
    return SDM_ERROR;
}
