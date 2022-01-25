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
#include <bitstream_actions.h>
#include <bitstream_section.h>
#include <config_state_machine.h>
#include <comp_config.h>
#include <sdm_trace.h>
#include <error_codes.h>
#include <decomp.h>
#include <config_keys_fifo.h>
#include <socal.h>
#include <sdm_timeout.h>
#include <cnoc.h>



/*! @addtogroup cmf_action_setup_decomp Action Setup Decompression
@{
This section specifies the format of a Setup Decompression Action as described in Section X.X.X of the
[Nadder Configuration Data Formats](http://rd/ice/product/Nadder/Documentation/FS/Nadder_Config_Data.docx).

This action sets up data tables within the decompression system for processing or more packets.  The
data to be loaded into the decompression system comes from data blocks following this one.

In most cases the decompression tables in both sides of the device will need to be set up in the same way.
The bitstream to do this will contain two copies of this action, one for each side of the device.

As the decompression system does not back pressure the data table load then putting two actions in the same
descriptor with non-interleaved data following will be no slower than interleaving the data but simpler to
implement.

The CMF must check that the data blocks which are first in the queue have data routing which matches the
destination field shown in the action.
@note The GZIP codebook is not used on Nadder.  On Falcon Mesa it contains the 2k byte literal table.

The literal table provides a mapping to be applied after inflate.  It is 256 entries, each tells DC how
to translate a particular byte value: the first entry provides the value to be output if inflate outputs
a 0 byte; the second entry provides the output value if inflate outputs a 1 byte etc.  Each entry contains
a single byte output value followed by 7 zero bytes.  The literal table allows the compressor to choose
which group of literal values are represented by 8 bits (the first 0x90 values) and which are represented
by 9 bits (the remaining 0x70 values).  Within each group the bytes should be in ascending order.
*/

/*! This is the index for the decompression engine which has values 0 and 1 as the only value. */
#define MAX_DECOMPRESSION_ENGINES (uint32_t) 1

#define AES_BLOCK_MULTIPLIER (0x1000)

/*!
This is the rather long CNOC timer based timeout for receiving decompression
setup information.
 */
#define ACTION_SETUP_DECOMP_TIMEOUT     0x40000000

/*!
@brief if aes encryption enabled for this action, then get one or two aes keys, as needed

@param setup_decomp_action pointer to SETUP_DECOMP action header structure
@param aes_action_key_type pointer to key type structure which will be filled in with the if we successfully get a key
@param aes_context_id pointer to integer which is filled in with the aes context ID, if we get a key for DC0
@param encrypt_enabled pointer to boolean which is filled in with true if encrypt enabled, and successfully get key(s)

@return Returns CMF_SUCCESS if encryption id not enabled, CMF_SUCCESS if enabled and successfully
got the keys requested, and an error code otherwise
 */
sdm_return_t setup_decomp_check_encryption(setup_decompression_action_t * setup_decomp_action,
                                           cmf_keys_fifo_key_type_t * aes_action_key_type,
                                           uint32_t * aes_context_id,
                                           bool * encrypt_enabled)
{
    sdm_return_t status = SDM_ERROR;
    uint32_t *init_vectors = NULL;
    cmf_keys_fifo_key_type_t local_aes_action_key_type = AES_KEYS_INVALID;

    // make sure all pointers are valid
    if((false == sdm_ram_ptr_valid(setup_decomp_action, sizeof(setup_decompression_action_t))) ||
       (false == sdm_ram_ptr_valid(aes_context_id, sizeof(uint32_t))) ||
       (false == sdm_ram_ptr_valid(encrypt_enabled, sizeof(bool))))
    {
        return(SDM_ERROR);
    }

    // if aes encryption enabled for this action, then get a key to be used to decrypt
    // data associated with this action
    // TODO: should check for all known values, and default should be an error return.
    if(setup_decomp_action->aes_key_selection == DECOMP_AES_KEY_SELECTION_TYPE_ENCRYPTED)
    {
        if(setup_decomp_action->destination == ALT_SDM_INBUF_FIFO_DC0)
        {
            local_aes_action_key_type = AES_KEYS_DC0_KEY;
        }
        else
        {
            local_aes_action_key_type = AES_KEYS_DC1_KEY;
        }
#ifdef UNIT_TEST
                uint8_t* u8Ptr = (uint8_t *)(void *)&setup_decomp_action[0];
                u8Ptr += sizeof(setup_decompression_action_t);
                init_vectors = (uint32_t *)u8Ptr;
#else
        // get a pointer to the initialization vectors for this action       
        if(true == __builtin_uadd_overflow((unsigned int )&setup_decomp_action[0],
                                           sizeof(setup_decompression_action_t), (unsigned int *)&init_vectors))
        {
            return(SDM_ERROR);
        }
#endif
        // get an aes key to decrypt the data for this action
        status = cmf_keys_fifo_get_action_key(local_aes_action_key_type, init_vectors);
        if(status == SDM_SUCCESS)
        {
            // get the aes context ID where the key is stored.
            status = cmf_keys_fifo_get_aes_context_id(local_aes_action_key_type, aes_context_id);
        }

        if(status != SDM_SUCCESS)
        {
            // free the aes context if we've allocated any before exiting with an error
            cmf_keys_fifo_key_done(local_aes_action_key_type);
            return(status);
        }

        // encryption is enabled for this action and we successfully got a key, so indicate
        // that we must use aes decryption, and return the aes key type
        *encrypt_enabled = true;
        *aes_action_key_type = local_aes_action_key_type;
    }

    return(SDM_SUCCESS);
}

void setup_decomp_aes_key_free(bool encrypt_enabled,
                               cmf_keys_fifo_key_type_t aes_action_key_type)
{
    if(encrypt_enabled)
    {
        // in case encryption was enabled, indicate that use of the aes key is complete
        cmf_keys_fifo_key_done(aes_action_key_type);
    }
}



/*!
Writes the Codebook to the Specified Decompression Engine

@param comp_config_handle is a valid handle to the composite configuration driver.
@param decomp_id specifies the decompression instance to write to.
@param table is the table type specified in the setup_decomp action.
@param size is the number of blocks to send to the decompression block.
@param encryption is the type of encryption to use or DECOMP_AES_KEY_SELECTION_TYPE_NONE
to disable decryption.

@note This handle must never be stored in anything but a local stack variable and not any
global state.

@return Returns SDM_SUCCESS if the codebook was written or SDM_ERROR
*/
static sdm_return_t setup_decomp_write_codebook(comp_config_handle_t comp_config_handle,
                                               decomp_id_t decomp_id,
                                               decomp_table_type_t table,
                                               uint32_t block_count,
                                               cmf_keys_fifo_key_type_t aes_action_key_type,
                                               uint32_t aes_context_id,
                                               bool encryption)
{

    sdm_return_t ret = SDM_ERROR;
    decomp_handle_t decomp_handle = (decomp_handle_t)SDM_HANDLE_INVALID;
    cnoc_handle_t cnoc_handle = comp_config_cnoc_handle_get(comp_config_handle);

    if(decomp_id >= DECOMP_ID_NUM_ENGINES)
    {
         return(ret);
    }

    if(decomp_id == DECOMP_ID_0)
    {
        decomp_handle = comp_config_decomp0_handle_get(comp_config_handle);
    }
    else if(DECOMP_ID_NUM_ENGINES > 1)
    {
        decomp_handle = comp_config_decomp1_handle_get(comp_config_handle);
    }

    uint32_t out_count = 0;
    uint32_t block_size = SDM_INBUF_PACKET_BYTE_SIZE;
    bool no_dest_mode = false;
    uint32_t cnoc_timeout = 0;

    // confirm perihperal driver handles are valid
    if((decomp_handle == (decomp_handle_t)SDM_HANDLE_INVALID))
    {
        SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
        return(SDM_ERROR);
    }

    if(cnoc_handle == (cnoc_handle_t)SDM_HANDLE_INVALID)
    {
        SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
        return(SDM_ERROR);
    }

    // restart the decomp engine and set to decompress mode
    ret = decomp_restart(decomp_handle);
    if(ret != SDM_SUCCESS)
    {
        SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
        return(SDM_ERROR);
    }
    ret = decomp_mode_set(decomp_handle, DECOMP_MODE_DECOMPRESS);
    if(ret != SDM_SUCCESS)
    {
        SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
        return(SDM_ERROR);
    }

    ret = decomp_method(decomp_handle, HAL_DECOMP_METHOD_STORE);
    if(ret != SDM_SUCCESS)
    {
        SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
        return(SDM_ERROR);
    }

    switch(table)
    {
        case DECOMP_TABLE_GZIP_CODEBOOK:
            ret = decomp_memory_mode_set(decomp_handle, DECOMP_MEMORY_CODEBOOK);
            if(ret != SDM_SUCCESS)
            {
                SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
                return(SDM_ERROR);
            }
            // half the block will be sent with MEMORY_CODEBOOK mode set,
            // the second half will be sent with NODEST set
            no_dest_mode = false;
            block_size = SDM_INBUF_PACKET_BYTE_SIZE >> 1;
            break;

        case DECOMP_TABLE_2D_IP_LIBRARY:
            ret = decomp_memory_mode_set(decomp_handle, DECOMP_MEMORY_2DLIB);
            if(ret != SDM_SUCCESS)
            {
                SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
                return(SDM_ERROR);
            }
            break;

        case DECOMP_TABLE_2D_SECTOR:
            ret = decomp_memory_mode_set(decomp_handle, DECOMP_MEMORY_2DSECTOR);
            if(ret != SDM_SUCCESS)
            {
                SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
                return(SDM_ERROR);
            }
            break;

        default:
            break;
    }


    do
    {
        // Now try to get a block of data
	   if(decomp_id == DECOMP_ID_0)
         {
            ret = comp_config_get_dc0_block(comp_config_handle, encryption, aes_context_id, block_size);
            if(ret == SDM_ERROR)
            {
               SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
            }
         }
	   else if(DECOMP_ID_NUM_ENGINES > 1)
         {
            ret = comp_config_get_dc1_block(comp_config_handle, encryption, aes_context_id, block_size);
            if(ret == SDM_ERROR)
            {
               SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
            }
         }

        // check if we successfully got a block of data, or maybe the AES was busy or
        // maybe inbuf was empty?
        if(ret == SDM_SUCCESS)
        {
            // update the number of blocks output
            if(table == DECOMP_TABLE_GZIP_CODEBOOK)
            {
                uint32_t status = 0;
                ret = decomp_status_get(decomp_handle, &status);
                if(ret != SDM_SUCCESS)
                {
                    break;
                }

                // make sure AES transfer completed before sending the second half
                cnoc_timeout = cnoc_timer_value_get(cnoc_handle);
                while ((alt_sdm_aes_ready() == 0)  && ((status & DECOMP_STATUS_INFIFO_EMPTY) != 0x0))
                {
                    ret = decomp_status_get(decomp_handle, &status);
                    if(ret != SDM_SUCCESS)
                    {
                        break;
                    }

                    if(cnoc_timer_timeout(cnoc_handle, cnoc_timeout, ACTION_SETUP_DECOMP_TIMEOUT))
                    {
                        SDM_TRACE_INFO(TRACE_ERROR_TIMEOUT, __LINE__);
                        setup_decomp_aes_key_free(encryption,
                                                    aes_action_key_type);
                        return(SDM_ERROR_TIMEOUT);
                    }
                }

                // if we've completed the second half of the block, which is the no_dest portion,
                // then update the out_count
                if(no_dest_mode == true)
                {
                    out_count++;
                    no_dest_mode = false;
                    // set up the memory mode for codebook for the first half of the next block.
                    ret = decomp_memory_mode_set(decomp_handle, DECOMP_MEMORY_CODEBOOK);
                    if(ret != SDM_SUCCESS)
                    {
                        SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
                    }
                }
                else
                {
                    no_dest_mode = true;
                    // set up the memory mode for no_dest for the second half of the block
                    ret = decomp_memory_mode_set(decomp_handle, DECOMP_MEMORY_NODEST);
                    if(ret != SDM_SUCCESS)
                    {
                        SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
                    }
                }
            }
            else
            {
                out_count++;
            }

            ret = bitstream_advance(block_size);
            if(ret != SDM_SUCCESS)
            {
                SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
                setup_decomp_aes_key_free(encryption,
                                          aes_action_key_type);
                return SDM_ERROR;
            }
            else
            {
                if(decomp_id == DECOMP_ID_0)
                {
                    SDM_TRACE_CONFIG(TRACE_GET_DC0_BLOCK, __LINE__);
                }
                else
                {
                    SDM_TRACE_CONFIG(TRACE_GET_DC1_BLOCK, __LINE__);
                }
            }
        }
        else if ((ret == SDM_ERROR_INBUF_EMPTY) || (ret == SDM_ERROR_BUSY))
        {
            // nothing to do here, just waiting for data
            // Do no timeout while waiting for the configuration host send config data (Refer HSD:1508159527)
            // The guiding principle is that the device does not timeout waiting for bitstream to arrive from the data source, 
            // instead the FW should check for config interruption (config_state_interrupted)
            // For debug purposes, if it is suspected that config host does send data in a timely manner, timeout can be added to check the same.
            // SDM_TRACE_INFO(TRACE_SECTOR_GROUP_WAITING_DC1, __LINE__);
            config_state_check_interruption();

            if (config_state_interrupted())
            {
                set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BITSTREAM_INTERRUPTED), 0);
                SDM_TRACE_ERROR(TRACE_BITSTREAM_INTERRUPT, __LINE__);
                ret = SDM_ERROR_ABORT;                  
            }
            else
            {                       
                ret = SDM_SUCCESS;
            }
            // SDM_TRACE_INFO(TRACE_SECTOR_GROUP_WAITING_AES_BUSY, __LINE__);
        }
        else
        {
            // An error occured
            SDM_TRACE_INFO(TRACE_ERROR, __LINE__);

            // abort if bitstream interrupt happen
            config_state_check_interruption();

            if (config_state_interrupted())
            {
                set_config_state_error(CREATE_ERROR_CODE(ERR_BITSTREAM_ERROR, BITSTREAM_INTERRUPTED), 0);
                SDM_TRACE_ERROR(TRACE_BITSTREAM_INTERRUPT, __LINE__);
                ret = SDM_ERROR_ABORT; 
            }
        }

        // TODO: add a timeout here

        // check for decompression engine errors. if an error occured, then exit with error
        if(decomp_check_status_for_error(decomp_handle) != false)
        {
            SDM_TRACE_INFO(TRACE_ERROR, __LINE__);
            setup_decomp_aes_key_free(encryption,
                                        aes_action_key_type);
            return(SDM_ERROR);
        }
    }
    while((out_count != block_count) && (ret == SDM_SUCCESS));

    // wait for the AES operation to complete.
    cnoc_timeout = cnoc_timer_value_get(cnoc_handle);
    while(alt_sdm_aes_ready() == 0)
    {
        if(cnoc_timer_timeout(cnoc_handle, cnoc_timeout, ACTION_SETUP_DECOMP_TIMEOUT))
        {
            SDM_TRACE_INFO(TRACE_ERROR_TIMEOUT, __LINE__);
            setup_decomp_aes_key_free(encryption,
                                        aes_action_key_type);
            return(SDM_ERROR_TIMEOUT);
        }
    }

    // in case encryption was enabled, indicate that use of the aes key is complete
    setup_decomp_aes_key_free(encryption, aes_action_key_type);

    return ret;
}

/*!
@brief This function is called to handle the ACTION_SETUP_DECOMP action.

@param action is a pointer to the current setup decompression action.
@param handles is a pointer to a set of Driver Handles needed for this action

@return Returns a negative number if the actions failed to be processed
completely, or returns a positive number of bytes consumed by this function..
*/

sdm_return_t action_setup_decomp(setup_decompression_action_t const * const base_action, comp_config_handle_t config_handle)
{

    //Instantiate Action Context Passed in by Bitstream
    setup_decompression_action_t * action = (setup_decompression_action_t *) base_action;
    cmf_keys_fifo_key_type_t aes_action_key_type = AES_KEYS_INVALID;
    uint32_t aes_context_id = CMF_KEYS_FIFO_INVALID_AES_CONTEXT_ID;
    bool encrypt_enabled = false;

    SDM_TRACE_ACTIONS(TRACE_ACTION_SETUP_DECOMP, __LINE__);

    //Check Validity of Action Content
    if(action->desc_type != ACTION_SETUP_DECOMP)
    {
        return SDM_ERROR;
    }

    //Make sure data blocks follow
    if(action->num_blocks == 0)
    {
        return SDM_ERROR;
    }

    //Check Decompression Engine is valid
    if(action->destination > MAX_DECOMPRESSION_ENGINES)
    {
        return SDM_ERROR;
    }

    switch(action->table_type)
    {
        case DECOMP_TABLE_GZIP_CODEBOOK:
        case DECOMP_TABLE_2D_IP_LIBRARY:
        case DECOMP_TABLE_2D_SECTOR:
            break;

        default:
            return(SDM_ERROR);
     }

    switch(action->aes_key_selection)
    {
        case DECOMP_AES_KEY_SELECTION_TYPE_NONE:
        case DECOMP_AES_KEY_SELECTION_TYPE_ENCRYPTED:
            break;

        default:
            return(SDM_ERROR);
     }

    // if aes encryption enabled for this action, then get a key to be used to decrypt
    // data associated with this action
    sdm_return_t status = setup_decomp_check_encryption(action,
                                                &aes_action_key_type,
                                                &aes_context_id,
                                                &encrypt_enabled);
    if(status != SDM_SUCCESS)
    {
        return(status);
    }

    //
    // Always clear the sticky done bit in AES because we need it to check that
    // decompression has received all the data.
    //
#ifndef SETUP_DECOMPRESSION_UNITTEST
    alt_write_word(ALT_AES_CSR_INTRCLR_ADDR, ALT_AES_CSR_INTRCLR_DONE_SET_MSK);
#endif

    for( uint8_t v_Idx =0; v_Idx < DECOMP_ID_NUM_ENGINES; v_Idx++ )
    {
	  if(action->destination == v_Idx)
       {
         return (setup_decomp_write_codebook(config_handle, (decomp_id_t)v_Idx, action->table_type, action->num_blocks, aes_action_key_type, aes_context_id, encrypt_enabled ));
       }
    }

    return SDM_ERROR;
}

/*! @} */


