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
#include <stddef.h>
#include <stddef.h>
#include <hal.h>
#include <bitstream_actions.h>
#include <bitstream_section.h>
#include <config_action.h>
#include <sdm_block_alloc.h>
#include <comp_config.h>
#include <sdm_system.h>
#include <sdm_trace.h>
#include <sdm_timeout.h>
#include <sdm_cfg_status.h>
#include <bitstream_parse_section.h>
#include <config_state_machine.h>
#include <config_wipe.h>
#include <bitstream_multicast.h>
#include <in_buf.h>
#include <slot_table_compatible.h>
#include <inbuf_drain_mgr.h>
#include <config_keys_fifo.h>
#ifdef ENABLE_TEST_DEBUG
#include <test_debug.h>
#endif


/*! The current fixed data block count. */
static uint32_t g_fixed_count = 0;

/*! The flags for the current fixed block. */
static uint32_t g_fixed_flags = 0;

//! The number of bytes remaining in the current section.
uint32_t section_bytes_remain;
//! The number of bytes remaining in the bitstream.
uint32_t bitstream_position_bytes;
//
// The number of sections in a bitstream.
//
uint32_t num_sections;
bool ssbl_sync_block;

void bitstream_section_init()
{
    section_bytes_remain = 0;
    bitstream_position_bytes = 0;
    num_sections = 0;
}

sdm_return_t bitstream_advance(uint32_t size_bytes)
{
    if(section_bytes_remain < size_bytes)
    {
        return SDM_ERROR;
    }
    if((bitstream_position_bytes + size_bytes) < bitstream_position_bytes)
    {
        return SDM_ERROR;
    }
    section_bytes_remain -= size_bytes;
    bitstream_position_bytes += size_bytes;

    return SDM_SUCCESS;
}

void bitstream_num_sections_set(uint32_t sections)
{
    num_sections = sections+1;
}
uint32_t bitstream_num_sections_get(void)
{
    return num_sections;
}
void bitstream_num_sections_dec(void)
{
    if (num_sections > 0)
    {
        num_sections--;
    }
}

void bitstream_ssbl_sync_block_set(bool s)
{
    ssbl_sync_block = s;
}
bool bitstream_ssbl_sync_block_get(void)
{
    return ssbl_sync_block;
}

void bitstream_position_set(uint32_t pos)
{
    bitstream_position_bytes = pos;
}

uint32_t bitstream_position_get(void)
{
    return(bitstream_position_bytes);
}

void bitstream_section_bytes_set(uint32_t size)
{
    section_bytes_remain = size;
}

uint32_t bitstream_section_bytes_get(void)
{
    return(section_bytes_remain);
}

/*!
@brief Returns the number of fixed data block remaining.

@return Returns the number of fixed data block remaining.
 */
uint32_t bitstream_fixed_count_get(void)
{
    return(g_fixed_count);
}

/*!
@brief Returns the flags set for the current fixed action.

@return Returns the flags set for the current fixed action.
 */
uint32_t bitstream_fixed_flags_get(void)
{
    return(g_fixed_flags);
}

/*!
@brief Add a fixed action block.

@param num_blocks is the number of data blocks in this fixed action.
@param flags is the values in the fixed_flag_e enumerated values.

This function is used to notify the bitstream module that we are processing a new
FIXED action. This does not handle adding the blocks to the hardware and just maintains the
state of the fixed action while it is active.

@return Returns SDM_SUCCESS if the fixed action was added and SDM_ERROR if it was not.
 */
sdm_return_t bitstream_fixed_add(uint32_t num_blocks, uint32_t flags)
{
    sdm_return_t ret = SDM_ERROR;

    if(g_fixed_count == 0u)
    {
        g_fixed_count = num_blocks;
        g_fixed_flags = flags;
        ret = SDM_SUCCESS;
    }

    return(ret);
}

/*!
@brief Removes a data block from the bitstream queue.

@return Returns SDM_SUCCESS if the block was removed and SDM_ERROR if it was not.
 */
sdm_return_t bitstream_fixed_remove(void)
{
    sdm_return_t ret = SDM_ERROR;

    if(g_fixed_count != 0u)
    {
        g_fixed_count--;
        ret = SDM_SUCCESS;
    }

    //
    // Done with the fixed block so clear the flags.
    //
    if(g_fixed_count == 0u)
    {
        g_fixed_flags = 0;
    }
    return(ret);
}

sdm_return_t bitstream_fixed_flow(comp_config_handle_t config_handle)
{
    sdm_return_t ret_val = SDM_SUCCESS;
    if(bitstream_fixed_flags_get() & FIXED_FLAG_ATOMIC)
    {
        //
        // Wait for the hash queue get all the data blocks hashes
        //
#if defined(ENABLE_TEST_DEBUG) && !defined(EMULATOR)
        test_printf("Atomic\n");
        uint32_t backup_section_hash_count = 0;
        uint32_t backup_fixed_action_hash_count = 0;
#endif
        uint32_t section_hash_count = 0;
        uint32_t fixed_action_hash_count = 0;
        while (g_fixed_count > 1)
        {
            ret_val = hash_mgr_get_hash_count(comp_config_hash_mgr_handle_get(config_handle), &section_hash_count, &fixed_action_hash_count);
#if defined(ENABLE_TEST_DEBUG) && !defined(EMULATOR)
            if (section_hash_count != backup_section_hash_count)
            {
                test_printf("Section hash count: %d\n", section_hash_count);
                backup_section_hash_count = section_hash_count;
            }
            if (fixed_action_hash_count != backup_fixed_action_hash_count)
            {
                test_printf("Fixed hash count: %d\n", fixed_action_hash_count);
                backup_fixed_action_hash_count = fixed_action_hash_count;
            }
#endif
            if(ret_val != SDM_SUCCESS || section_hash_count == 0 || fixed_action_hash_count == 0)
            {
                break;
            }
            config_state_check_interruption();
            if (config_state_interrupted())
            {
                set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BITSTREAM_INTERRUPTED), 0);
                SDM_TRACE_INFO(TRACE_BITSTREAM_INTERRUPT, __LINE__);
                ret_val = SDM_ERROR_ABORT;
                break;
            }
        }
    }

    return ret_val;
}

/*!
Get a data block from designated inbuf fifo, DC0/DC1/KEY to NSP RAM 

@param handle is a valid handle to the composite configuration driver.
@param p_data is the address in NSP RAM for write DMA destination
@param fifo is the inbuf fifo select enum
*/
static sdm_return_t sdm_get_skip_data_block(comp_config_handle_t config_handle, uint32_t *p_action, in_buf_select_t fifo)
{
    uint64_t timer = 0;
    sdm_return_t ret_val = SDM_ERROR;

    do
    {
        ret_val = comp_config_get_skip_block(config_handle, (uint32_t *)p_action, BITSTREAM_DATA_BLOCK_SIZE_BYTES, fifo);
        if ((ret_val != SDM_SUCCESS) && (ret_val != SDM_ERROR_INBUF_EMPTY))
        {
            SDM_TRACE_ERROR(TRACE_BITSTREAM_ERROR, __LINE__);
        }
        config_state_check_interruption();
        if (config_state_interrupted())
        {
            SDM_TRACE_INFO(TRACE_BITSTREAM_INTERRUPT, __LINE__);
            ret_val = SDM_ERROR_ABORT;
        }

    } while(ret_val == SDM_ERROR_INBUF_EMPTY);

    if (ret_val != SDM_SUCCESS)
    {
        return ret_val;
    }

    // poll DMA is done
    timer = sdm_timeout_init(BITSTREAM_DATA_BLOCK_SIZE_BYTES * 100);
    while(comp_config_check_dma_write_done(config_handle) == false)
    {
        if(sdm_timeout(timer))
        {
            config_state_check_interruption();
            if(config_state_interrupted())
            {
                SDM_TRACE_ERROR(TRACE_BITSTREAM_INTERRUPT, __LINE__);
                ret_val = SDM_ERROR_ABORT;
            }
            else
            {
                sdm_cfg_status_set_state(SDM_CFG_STATUS_CFGSTAT_STATE_ERROR_HARDWARE);

                SDM_TRACE_ERROR(TRACE_BITSTREAM_ERROR, __LINE__);
                ret_val = SDM_ERROR;
            }
            return ret_val;
        }
    }

    return SDM_SUCCESS;
}        


static sdm_return_t sdm_get_action_block(comp_config_handle_t config_handle, uint32_t *p_action, bool hash_check)
{
    uint64_t timer = 0;
    sdm_return_t ret_val = SDM_ERROR;

    //Routes from main descriptors already added to inbuf fill mgr
    //which started sha as well

    do
    {
        ret_val = comp_config_get_cpu_block(config_handle, (uint32_t *)p_action, BITSTREAM_DATA_BLOCK_SIZE_BYTES, hash_check);

        if ((ret_val != SDM_SUCCESS) && (ret_val != SDM_ERROR_INBUF_EMPTY))
        {
            SDM_TRACE_ERROR(TRACE_BITSTREAM_ERROR, __LINE__);
        }

        config_state_check_interruption();
        if (config_state_interrupted())
        {
            SDM_TRACE_INFO(TRACE_BITSTREAM_INTERRUPT, __LINE__);
            ret_val = SDM_ERROR_ABORT;
        }
    } while(ret_val == SDM_ERROR_INBUF_EMPTY);

    if (ret_val != SDM_SUCCESS)
    {
        return ret_val;
    }

    // poll DMA is done
    timer = sdm_timeout_init(BITSTREAM_DATA_BLOCK_SIZE_BYTES * 100);
    while(comp_config_check_dma_write_done(config_handle) == false)
    {
        if(sdm_timeout(timer))
        {
            config_state_check_interruption();
            if(config_state_interrupted())
            {
                SDM_TRACE_ERROR(TRACE_BITSTREAM_INTERRUPT, __LINE__);
                ret_val = SDM_ERROR_ABORT;
            }
            else
            {
                SDM_TRACE_ERROR(TRACE_BITSTREAM_ERROR, __LINE__);
                ret_val = SDM_ERROR;
            }

            return ret_val;
        }    
    }

    if(bitstream_advance(BITSTREAM_DATA_BLOCK_SIZE_BYTES) != SDM_SUCCESS)
    {
         return SDM_ERROR;
    }

    return SDM_SUCCESS;
}

/*!
This function is to skip data blocks from a configuration bitstream where routes is queued up
earlier to be able to fill up input buffer. This skip is to direct input FIFO DC0 and FIFO
DC1 data to bypass AES and DMA into NSP ram and discard.

@param blocks is the number of data blocks to skip from configuration bitstream.

@return Returns SDM_SUCCESS if successful and SDM_ERROR if there was any problem.
 */
static sdm_return_t skip_config_data(comp_config_handle_t config_handle, uint32_t blocks)
{
    uint32_t skip_blocks = blocks;
    in_buf_select_t route;
    OS_ERR err = OS_ERR_Z;
    sdm_return_t ret = SDM_ERROR;
    base_action_t * action = NULL;


    while(skip_blocks)
    {
        SDM_TRACE_INFO(TRACE_GENERIC_INFO, skip_blocks);
        //Always check DC0 first, if single data block to skip, shall be DC0

        config_state_check_interruption();
        if (config_state_interrupted())
        {
            // pre-interruption gets processed as part of check interruption API so just need to return to caller
            // to get back to state machine to handle new added events
            SDM_TRACE_ERROR(TRACE_BITSTREAM_INTERRUPT, __LINE__);
            return(SDM_ERROR_ABORT);
        }

        route = comp_config_get_current_route(config_handle);

        // Input buffer under-run in HPS streaming
        if (route == IN_BUF_FIFO_INVALID)
        {
            OSTimeDly(2, OS_OPT_TIME_DLY, &err);
            continue;
        }
        //
        // Get a new action buffer.
        //
        action = (base_action_t *)sdm_block_alloc();
        if(action == NULL)
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return SDM_ERROR;
        }

        ret = sdm_get_skip_data_block(config_handle, (uint32_t *)action, route);
        if (ret == SDM_SUCCESS)
        {
            skip_blocks--;
        }
        else
        {
            sdm_block_free(action);
            SDM_TRACE_INFO(TRACE_MEMORY_FREE, action);
            // check the skip data eror returned
            check_action_block_error(ret, SKIP_DATA_RAM_FAIL);

            return ret;
        }

        //free allocated buffer
        sdm_block_free(action);
        SDM_TRACE_INFO(TRACE_MEMORY_FREE, action);
    }
    return SDM_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS
///////////////////////////////////////////////////////////////////////////////////////////////////

sdm_return_t bitstream_section(comp_config_handle_t config_handle,
                               main_descriptor_t const * main_descriptor,
                               signature_descriptor_t const * signature_descriptor)
{
    sdm_return_t ret = SDM_SUCCESS;
    uint32_t section_bytes_remaining = 0;
    bool Fixed_group_enter = false;

    g_fixed_count = 0;
    g_fixed_flags = 0;

    if((sdm_ram_ptr_valid(main_descriptor, sizeof(main_descriptor_t)) == false) ||
       (sdm_ram_ptr_valid(signature_descriptor, sizeof(signature_descriptor_t)) == false))
    {
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
        return SDM_ERROR;
    }

    while(ret == SDM_SUCCESS)
    {
        bool hash_check = true;
        if(cmf_action_empty() == true)
        {
            base_action_t * action = NULL;
            //
            // Get a new action buffer.
            //
            action = (base_action_t *)sdm_block_alloc();

            if(action == NULL)
            {
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                return SDM_ERROR;
            }
            if (config_wipe_active())
            {
                hash_check = false;
            }
            ret = sdm_get_action_block(config_handle, (uint32_t *)action, hash_check);
            if (ret != SDM_SUCCESS)
            {
                sdm_block_free(action);
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                // check the block error returned
                check_action_block_error(ret, CPU_BLK_FAIL);
                return ret;
            }

            if(cmf_action_add(action) != SDM_SUCCESS)
            {
                sdm_block_free(action);
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                ret = SDM_ERROR;
            }
            sdm_block_free(action);
        }

        ret = config_action_handler(config_handle, main_descriptor);
        if (ret == SDM_SUCCESS)
        {
            //Process Fixed action's special flow
            if (cmf_action_is_current_fixed())
            {
                ret = bitstream_fixed_flow(config_handle);
                if (ret == SDM_SUCCESS)
                {
                    Fixed_group_enter = true;
                }
                else 
                {
                    SDM_TRACE_ERROR(TRACE_ERROR_ACTION_INVALID, __LINE__);
                    break;
                }
            }
        }
        else
        {
            SDM_TRACE_ERROR(TRACE_ERROR_ACTION_INVALID, __LINE__);
            break;
        }

        // 
        // Move to the next action.
        //
        ret = cmf_action_inc();
        if(ret != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ERROR_ACTION_INVALID, __LINE__);
            break;
        }

        config_state_check_interruption();
        if (config_state_interrupted())
        {
            set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BITSTREAM_INTERRUPTED), 0);
            SDM_TRACE_INFO(TRACE_BITSTREAM_INTERRUPT, __LINE__);
            ret = SDM_ERROR_ABORT;
            break;
        }

        if((cmf_action_empty() == true) &&
            (bitstream_fixed_count_get() > 0u) &&
            (Fixed_group_enter == true))
        {
            // Action block shall be freed already upon action_inc reaches the end.
            // Now reduce fixed count for the fixed action block itself
            if(bitstream_fixed_remove() != SDM_SUCCESS)
            {
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            }
            //
            // Check if we are finish up a Fixed action group
            //
            if (bitstream_fixed_count_get() == 0)
            {
                Fixed_group_enter = false;
    
                //free mcast list, fuse filter list and action_if context
                multicast_list_clear();
                fuse_filter_clear();
                action_if_init();
            }
        }

        // get the number of bytes remaining in the section to determine if processing of this
        // section is complete
        section_bytes_remaining =  bitstream_section_bytes_get();
        if((section_bytes_remaining == 0) && (cmf_action_empty() == true))
        {
            // Finished a section 
            break;
        }
    }

    //End of a section, might also be a wipe bitstream ends
    if ((ret == SDM_SUCCESS) && (!config_wipe_active()))
    {
        ret = update_section_slot(main_descriptor);
        if (ret != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return ret;
        }
        if(main_descriptor->desc_type == DESC_TYPE_CORE ||
            main_descriptor->desc_type == DESC_TYPE_PR)
        {
            // We have the new image loaded, so update the list of
            // PR regions that can be loaded now 
            update_pofID(main_descriptor);
        }
        if(bitstream_num_sections_get() > 0)
        {
            //
            // check if we finished IO section and HPS is present
            //
            if(hal_has_hps())
            {
                if (action_if_get_hps_present() &&
                    ((main_descriptor->desc_type == DESC_TYPE_IO) ||
                     (main_descriptor->desc_type == DESC_TYPE_HPIO) ||
                     (main_descriptor->desc_type == DESC_TYPE_FBRC)) )
                {
                    config_state_set_hpio_ready(true);
                }
            }
        }
    }
    else if (Fixed_group_enter)
    {
        Fixed_group_enter = false;
        multicast_list_clear();
        fuse_filter_clear();
        action_if_init();        
    }

    return ret;
}


/*!
This function is called to skip the data associated with an action if we are
processing a conditional block that needs to be skipped.

@param blocks is the number of data blocks to skip.

@return Returns SDM_SUCCESS if successful and SDM_ERROR or SDM_ERROR_ABORT if there was any problem.
 */
sdm_return_t crypto_skip_data(comp_config_handle_t config_handle, uint32_t blocks)
{
    uint32_t size = 0;
    uint32_t i = 0;
    uint32_t skip_action_blocks = 0;
    sdm_return_t skip_ret = SDM_ERROR;

    SDM_TRACE_ACTIONS(TRACE_SKIP_DATA_BLOCK, blocks);

    //
    // Cannot skip partial blocks so we must have all block for this action
    // skipped.
    //
    if(bitstream_fixed_count_get() < blocks)
    {
        return SDM_ERROR;
    }
    
    // current if action's should have enough blocks to skip, skip them by reading into NSP ram
    // and throw away.
    // Skipping data blocks without If action trigger, then has to ignore the check with IF_action's
    // number of skip blocks.
    //
    skip_action_blocks = action_if_num_skip_blocks_get();
    if ((skip_action_blocks > 0) && (blocks > skip_action_blocks))
    {
        return SDM_ERROR;
    }
    skip_ret = skip_config_data(config_handle, blocks);

    if(skip_ret != SDM_SUCCESS)
    {
        return skip_ret;
    }
    //
    // Calculate the number of bytes to skip, as skip_config_data() has been successful
    //
    size =  blocks * BITSTREAM_DATA_BLOCK_SIZE_BYTES;
    if(bitstream_advance(size) != SDM_SUCCESS)
    {
         SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
         return SDM_ERROR;
    }

    //if blocks is bigger than IF_action's num_skip_blocks, then don't update If_action
    if (blocks <= skip_action_blocks)
    {
        action_if_num_skip_blocks_decrement(blocks);
    }

    for(i = 0; i < blocks; i++)
    {
        if(bitstream_fixed_remove() != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return SDM_ERROR;
        }

        // For configuration and wipe bitstream, skip data blocks is to direct blocks to bypass AES
        // and DMA write to NSP RAM, then through away. No need to compare hash. Fixed block hash
        // is just throw away.
    }
    return SDM_SUCCESS;
}

/*!
check for error type relate to data block failure
@param  error_ret is the error returned from data block actions
@return None
*/
void __attribute__ ((noinline)) check_action_block_error(sdm_return_t error_ret, uint32_t error_code)
{
    if(error_ret == SDM_ERROR_ABORT)
    {
        set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BITSTREAM_INTERRUPTED), 0);
        SDM_TRACE_ERROR(TRACE_BITSTREAM_INTERRUPT, __LINE__);
    }
    else
    {
        if (error_ret == SDM_ERROR_MISCOMPARE)
        {
            set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_CORRUPTION, BS_INVALID_SHA), 0);
            SDM_TRACE_ERROR(TRACE_BITSTREAM_ERROR, __LINE__);
        }
        else 
        {
            set_config_state_error(CREATE_ERROR_CODE(ERR_INTERNAL_ERROR, error_code), 0);
        }
        // untolerable Error during wipe, treat it as fatal
        if(config_wipe_active() == true)
        {
            config_wipe_error_set(true);
        }
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
    }
}



