/*
INTEL CONFIDENTIAL
Copyright (2021) Intel Corporation

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
#include <string.h>
#include <sdm_system.h>
#include <hal.h>
#include <mbox_hw_mgr.h>
#include <mbox_hw_mgr_fpga.h>
#include <mbox_hw_mgr_jtag.h>
#include <mbox_q.h>

#include <hal.h>
#include <alt_jtag.h>

#include <clkmgr.h>
#include <error_codes.h>

#include "nd/clkmgr_priv.h"
#include <config_clock.h>
#include <sdm_timeout.h>

#include <int_control.h>
#include <config_state_machine.h>
#include <config_flags.h>
#include <os.h>

#include <system_control.h>
#include <anti_tamper.h>
#include <sensor_main.h>
#include <bitstream.h>
#include <pmf.h>
#include <timers.h>
#include <persistent.h>

#include <sdm_trace.h>
#include <pin_functions.h>

#include <mbox_hw_mgr_hps.h>
#include <mbox_task.h>
#include <mbox_common.h>

#include <efuse_cmf_access.h>

#include <bbram_drv.h>
#include <config_aes_ops.h>
#include <ukv_drv.h>
#include <hal_efuse.h>

#include <dma_drv.h>
#include <aes_drv.h>
#include <cmf_aes.h>
#include <config_aes.h>
#include <alt_key_vault.h>
#include <cmf_key.h>
#include <cmf_km.h>
#include <in_buf.h>

#ifdef ENABLE_ANTI_TAMPER

#include <anti_tamper_priv.h>

STATIC anti_tamper_context_t s_anti_tamper_ctx =
{
    .table = {},
    .valid = false,

    .volt_det_suspended = 0,
    .fpga_zerorize_reqested = 0,

    .upr_temp_signed = 0,
    .lwr_temp_signed = 0,

    .num_vadc_ch  = NUM_VADC_MONITOR_CH,

    .vadc_ch_mask = 0,

    .trigger_reason_mask = 0,

    .zerorization_status = 0,
    .zerorization_mask = 0,
    .init_status = 0,
    .enable_status = 0
};

// Anti-tamper fpga response done timer.
static timer_handle_t s_anti_tamper_timer = (timer_handle_t)SDM_HANDLE_INVALID;


void anti_tamper_enable_status_set(uint32_t mask)
{
    s_anti_tamper_ctx.enable_status |= mask;
}

uint32_t anti_tamper_enable_status_get(void)
{
    return s_anti_tamper_ctx.enable_status;
}

void anti_tamper_enable_status_clr(uint32_t mask)
{
    s_anti_tamper_ctx.enable_status &= ~mask;
}

void anti_tamper_init_status_set(uint32_t mask)
{
    s_anti_tamper_ctx.init_status |= mask;
}

uint32_t anti_tamper_init_status_get(void)
{
    return s_anti_tamper_ctx.init_status;
}

void update_anti_tamper_zerorization_mask(uint32_t mask)
{
    s_anti_tamper_ctx.zerorization_mask |= mask;
}

void anti_tamper_zerorization_status_set(uint32_t mask)
{
    s_anti_tamper_ctx.zerorization_status |= mask;
    anti_tamper_update_boot_status();
}

void anti_tamper_set_vadc_ch_mask(uint32_t mask)
{
    s_anti_tamper_ctx.vadc_ch_mask |= mask;
}

uint32_t anti_tamper_get_vadc_ch_mask(void)
{
    return s_anti_tamper_ctx.vadc_ch_mask;
}

uint32_t anti_tamper_get_num_vadc_ch()
{
    return s_anti_tamper_ctx.num_vadc_ch;
}

static void anti_tamper_update_vadc_ch_mask(void)
{
    // Update vadc mask for vccl if enabled
    if (get_atpr_vccl_enable() == ATPR_ENABLE)
    {
        anti_tamper_set_vadc_ch_mask((uint32_t)ANTI_TAMPER_VADC_CH_VCCL_MASK);
    }

    // Update vadc mask for vccl_sdm if enabled 
    if (get_atpr_vccl_sdm_enable() == ATPR_ENABLE)
    {
        anti_tamper_set_vadc_ch_mask((uint32_t)ANTI_TAMPER_VADC_CH_VCCL_SDM_MASK);
    }
}

/*!
This function returns the vccl range in the anti-tamper table
Warning: This function should not be used before building the table

@return Returns vccl lower threshold in the anti-tamper table
 */
uint32_t anti_tamper_get_voltage_range(void)
{
    return ATPR_VOLTAGE_RANGE_PCT(s_anti_tamper_ctx.table.voltage_cfg);
}

/*!
This function returns the state of the anti tamper global
tamper detection enable. If s_anti_tamper_ctx is not valid
(the value has not being initialized) ATPR_TYPE_INVALID will be
returned.

@return Returns global tamper detection value.
 */
atpr_response_type_t anti_tamper_get_global_enable(void)
{
    if (anti_tamper_table_valid())
    {
        return (atpr_response_type_t)ATPR_RESP_CATEGORY(s_anti_tamper_ctx.table.anti_tamper_cfg);
    }
    else
    {
        return ATPR_TYPE_INVALID;
    }
}

/*!
@brief Query if fpga tamper detection is enabled
@param None
@return ATPR_DISABLE if disabled, ATPR_ENABLE if enabled
 */
atpr_enable_t anti_tamper_get_fpga_enable(void)
{
    //Verify global enable, get_atpr_global_enable verifies that the table is valid
    if(anti_tamper_get_global_enable() != ATPR_TYPE_INVALID)
    {
        //If the response is enabled check the feature enabling
        return (atpr_enable_t)ATPR_FPGA_DETECTION(s_anti_tamper_ctx.table.anti_tamper_cfg);
    }
    else
    {
        return ATPR_DISABLE;
    }
}

/*!
This function validates that vccl range is correct in the anti-tamper table.
The function will return true if voltage detection is enabled and the 
range values are valid

@return true if the value in vccl is valid.
 */
static bool is_atpr_voltage_valid(void)
{
    if(anti_tamper_get_voltage_enable() == ATPR_ENABLE)
    {
        uint32_t range = anti_tamper_get_voltage_range();
        //VCCL enableds, validate ranges
        return ((range >=  ATPR_VOLT_RANGE_LWR_LIMIT) && (range <=  ATPR_VOLT_RANGE_UPR_LIMIT));
    }
    else
    {
        //Since VCCL is not enabled, table is valid
        return true;
    }
}

/*!
This function validates that temperature thresholds are correct in the anti-tamper
table, the function will return true if temperature detection is enabled and the 
threshold values are between the limits 

@return true if the value in frequency range is valid.
 */
static bool is_atpr_temperature_valid(void)
{
    if((atpr_enable_t)ATPR_TEMP_DETECTION(s_anti_tamper_ctx.table.temperature_cfg) == ATPR_ENABLE)
    {
        //If enabled, validate threshold values
        return (s_anti_tamper_ctx.lwr_temp_signed <= s_anti_tamper_ctx.upr_temp_signed);
    }
    else
    {
        //Since it is not enabled values are not review
        return true;
    }
}

/*!
This function validates the entries of the anti-tamper table, if the entries
are valid, s_anti_tamper_ctx.valid will be set to true. s_anti_tamper_ctx.valid
will be false otherwise.
 */
void validate_anti_tamper_table(void)
{
    //Check if the global enable settings are valid
    if(is_valid_global_atpr_enable())
    {
        //Only valid if all individual settings are valid
        s_anti_tamper_ctx.valid = (is_atpr_frequency_valid() && is_atpr_temperature_valid() &&
            is_atpr_voltage_valid());
    }
    else
    {
        //Since global valids are wrong the table will de disable
        s_anti_tamper_ctx.valid = false;
    }
}

/*!
This function validates that global enable settings are correct in the anti-tamper table

@return true if the setting for global tamper detection are valid
 */
STATIC bool is_valid_global_atpr_enable(void)
{
    atpr_response_type_t resp_category = (atpr_response_type_t)ATPR_RESP_CATEGORY(s_anti_tamper_ctx.table.anti_tamper_cfg);
    bool resp_cat_ii_to_iv = (resp_category >= ATPR_TYPE_II) && (resp_category <= ATPR_TYPE_IV);

    if (ATPR_GLOBAL_DETECTION(s_anti_tamper_ctx.table.anti_tamper_cfg))
    {
        // Not valid if global kill enabled and either self kill fuse not blown or wrong category
        return !(ATPR_GLOBAL_KILL_ENABLED(s_anti_tamper_ctx.table.anti_tamper_cfg) &&
            (!is_permit_self_kill_fuse_blown() || !resp_cat_ii_to_iv));
    }
    // It is ok not to set global enable.
    return true;

}

/*!
This function initializes the anti-tamper table based on the main descriptor
for the IO section.

ToDo: to complete the logic to locate the offsets in the IO main descriptor and
populate the table

@return Returns initialization status
 */
sdm_return_t anti_tamper_table_init(const main_descriptor_t *main_descriptor)
{
    clear_anti_tamper_table();
    //Copy the elements of the antytamper table
    //Global response
    s_anti_tamper_ctx.table.anti_tamper_cfg.word = main_descriptor->global_anti_tamper_cfg;
    //Frequency configuration
    s_anti_tamper_ctx.table.frequency_cfg.word = main_descriptor->anti_tamper_freq_cfg;
    //Temperature configuration
    s_anti_tamper_ctx.table.temperature_cfg.word = main_descriptor->anti_tamper_temp_cfg;
    //Voltage configurationa
    s_anti_tamper_ctx.table.voltage_cfg.word = main_descriptor->anti_tamper_volt_cfg;

    s_anti_tamper_ctx.upr_temp_signed = get_temp_sign_extension(ATPR_TEMP_UPR_THOLD(s_anti_tamper_ctx.table.temperature_cfg));
    s_anti_tamper_ctx.lwr_temp_signed = get_temp_sign_extension(ATPR_TEMP_LWR_THOLD(s_anti_tamper_ctx.table.temperature_cfg));

    // We defer to set up mask for HPS and FPGA zerorization status since they are determined by bitstream
    s_anti_tamper_ctx.zerorization_mask = AT_RESPONSE_UKV_KEYREG_ZERORIZE_MSK
                                        | AT_RESPONSE_UKV_KEYRAM_ZERORIZE_MSK
                                        | AT_RESPONSE_EFUSE_KEY_ZERORIZE_MSK
                                        | AT_RESPONSE_SDM_ECC_ZERORIZE_MSK
                                        | AT_RESPONSE_SECTOR_ZERORIZE_MSK;

    // Add BBRAM zeroize mask if global enable is type IV.
    if((atpr_response_type_t)ATPR_RESP_CATEGORY(s_anti_tamper_ctx.table.anti_tamper_cfg) == ATPR_TYPE_IV)
    {
        s_anti_tamper_ctx.zerorization_mask |= AT_RESPONSE_BBRAM_KEY_ZERORIZE_MSK;
    }

    //Validate the table
    validate_anti_tamper_table();

    //Initlization code
    if(anti_tamper_table_valid())
    {
        return SDM_SUCCESS;
    }

    return SDM_ERROR;
}

#if defined(BLOCK_LEVEL_TESTS) || defined(UNIT_TEST)
/*!
This function validates the entries of the anti-tamper table, if the entries
are valid, s_anti_tamper_ctx.valid will be set to true. s_anti_tamper_ctx.valid
will be false otherwise.

Warning: This function is meant for enabling and debug only.

@param global tamper detection
@param voltage detection enable value
@param temperature detection enable value
@param frequency detection enable value
@param frequency range value
@param temperature upper threshold
@param temperature lower threshold
@param VCCL range value
@param VCCL SDM range value

@return True is the table is correct, false otherwise
 */
bool set_anti_tamper_table(
                     atpr_response_type_t global,
                     atpr_enable_t vccl,
                     atpr_enable_t vccl_sdm,
                     atpr_enable_t temp,
                     atpr_enable_t freq,
                     atpr_freq_t freq_range,
                     uint32_t upr_temp,
                     uint32_t lwr_temp,
                     uint32_t volt_range
                     )
{
    anti_tamper_global_config_t* p_anti_tamper_cfg = &(s_anti_tamper_ctx.table.anti_tamper_cfg);
    anti_tamper_temp_config_t* p_temperature_cfg = &(s_anti_tamper_ctx.table.temperature_cfg);
    anti_tamper_freq_config_t* p_frequency_cfg = &(s_anti_tamper_ctx.table.frequency_cfg);
    anti_tamper_volt_config_t* p_voltage_cfg = &(s_anti_tamper_ctx.table.voltage_cfg);

    //[-] Enable global
    //Set global response

    if ((global >= ATPR_TYPE_I) && (global <= ATPR_TYPE_IV))
    {
        SET_ATPR_GLOBAL_DETECTION(p_anti_tamper_cfg, 1);
    }
    else
    {
        SET_ATPR_GLOBAL_DETECTION(p_anti_tamper_cfg, 0);
    }

    SET_ATPR_RESP_CATEGORY(p_anti_tamper_cfg, global);

    //Set eneable
    if(temp == ATPR_ENABLE)
    {
        SET_ATPR_TEMP_DETECTION(p_temperature_cfg);
    } else {
        CLEAR_ATPR_TEMP_DETECTION(p_temperature_cfg);
    }

    //Set thresholds
    SET_ATPR_TEMP_UPR_THOLD(p_temperature_cfg, upr_temp);
    //Set enables
    SET_ATPR_TEMP_LWR_THOLD(p_temperature_cfg, lwr_temp);

    s_anti_tamper_ctx.upr_temp_signed = get_temp_sign_extension(ATPR_TEMP_UPR_THOLD(s_anti_tamper_ctx.table.temperature_cfg));
    s_anti_tamper_ctx.lwr_temp_signed = get_temp_sign_extension(ATPR_TEMP_LWR_THOLD(s_anti_tamper_ctx.table.temperature_cfg));

    //Set eneable
    if(freq == ATPR_ENABLE)
    {
        SET_ATPR_FREQ_DETECTION(p_frequency_cfg);
    } else {
        CLEAR_ATPR_FREQ_DETECTION(p_frequency_cfg);
    }
    //Set freq value
    SET_ATPR_FREQ_PCT(p_frequency_cfg, (uint32_t)freq_range);

    //[-] Voltage values
    //Move pointer to voltage
    //VCCL
    if(vccl == ATPR_ENABLE)
    {
        SET_ATPR_VCCL_DETECTION(p_voltage_cfg);
    } else {
        CLEAR_ATPR_VCCL_DETECTION(p_voltage_cfg);
    }
    //VCCL SDM
    if(vccl_sdm == ATPR_ENABLE)
    {
        SET_ATPR_VCCL_SDM_DETECTION(p_voltage_cfg);
    } else {
        CLEAR_ATPR_VCCL_SDM_DETECTION(p_voltage_cfg);
    }

    //Set the voltage value
    SET_ATPR_VOLTAGE_RANGE_PCT(p_voltage_cfg, volt_range);

    //Validate the table
    validate_anti_tamper_table();

    return anti_tamper_table_valid();
}
#endif


/*!
This function validates that the frequency is correct in the anti-tamper
table, the function will return true if frequency detection is enabled and the
frequency values are in a valid range

@return true if the value in frequency range is valid.
 */
STATIC bool is_atpr_frequency_valid(void)
{
    if((atpr_enable_t)ATPR_FREQ_DETECTION(s_anti_tamper_ctx.table.frequency_cfg) == ATPR_ENABLE)
    {
        //Get frequency range value
        atpr_freq_t frequency_val = anti_tamper_get_frequency_range();
        //If enabled verify the valid ranges
        return ((ATPR_FREQ_35_PCT == frequency_val) ||
                (ATPR_FREQ_40_PCT == frequency_val) ||
                (ATPR_FREQ_45_PCT == frequency_val) ||
                (ATPR_FREQ_50_PCT == frequency_val));
    }
    else
    {
        //Since it is not enabled values are not review
        return true;
    }
}

/*!
This function returns the state of the power table,
True if it is valid, false otherwise

@return Returns the state of the anti-tamper table.
 */
bool anti_tamper_table_valid(void)
{
    return(s_anti_tamper_ctx.valid);
}

/*!
This function invalids the power table
 */
void invalidate_anti_tamper_table(void)
{
    s_anti_tamper_ctx.valid = false;
}

/*!
@brief Turn on tamper detection based on anti-tamper table settings.
@param None
@return SDM_SUCCESS if init succeeds, error code otherwise
 */
sdm_return_t anti_tamper_detection_init(void)
{
    sdm_return_t status = SDM_SUCCESS;
    // initialize tamper reason bit mask to 0
    s_anti_tamper_ctx.trigger_reason_mask = 0;

    do
    {
        // if global enable not enabled, then don't enable any tamper detection,
        // but don't raise an error.
        if (ATPR_GLOBAL_DETECTION(s_anti_tamper_ctx.table.anti_tamper_cfg) == 0)
        {
            break;
        }

        if (anti_tamper_get_fpga_enable() == ATPR_ENABLE)
        {
            // fpga tamper detection is enabled in user_mode when interrupt pins are initialized
            status = anti_tamper_fpga_detect_init();
            if (status != SDM_SUCCESS)
            {
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                break;
            }
            status = anti_tamper_fpga_detect_enable();
            if (status != SDM_SUCCESS)
            {
                SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
                break;
            }
        }

        if (anti_tamper_get_voltage_enable() == ATPR_ENABLE)
        {
            // Update vadc channel mask before voltage detection
            anti_tamper_update_vadc_ch_mask();

            status = sensor_anti_tamper_volt_det_init(
                anti_tamper_get_voltage_range(),
                anti_tamper_get_num_vadc_ch(),
                anti_tamper_get_vadc_ch_mask()
            );

            if (status != SDM_SUCCESS)
            {
                SDM_TRACE_ERROR(TRACE_ANTI_TAMPER_VOLTAGE_INIT_ERROR, __LINE__);
                break;
            }

            status = sensor_anti_tamper_volt_det_enable(true, anti_tamper_get_vadc_ch_mask());
            if (status != SDM_SUCCESS)
            {
                SDM_TRACE_ERROR(TRACE_ANTI_TAMPER_VOLTAGE_ENABLE_ERROR, __LINE__);
                break;
            }
        }

        if (anti_tamper_get_temp_enable() == ATPR_ENABLE)
        {
            sensor_anti_tamper_temp_det_init();
            anti_tamper_init_status_set(ANTI_TAMPER_INIT_STATUS_TEMPERATURE);
            sensor_anti_tamper_temp_det_enable(true);
            anti_tamper_enable_status_set(ANTI_TAMPER_ENABLE_STATUS_TEMPERATURE);
        }

    } while(0);
    return status;

}

uint32_t anti_tamper_reason_get(void)
{
    return (uint32_t)(s_anti_tamper_ctx.trigger_reason_mask & 0x0000FFFF);
}

/*!
@brief This function set the bit location for anti-tamper trigger reason for later
 checkup and determine the priority of triggers. Also used for bootstatus at end of flow.
@param  bit_position is the anti-tamper reason bit mask position, defined in anti_tamper.h
*/
void anti_tamper_reason_set(uint32_t bit_position)
{
    uint16_t mask = (0x1 << bit_position);
    s_anti_tamper_ctx.trigger_reason_mask &= ~mask;
    s_anti_tamper_ctx.trigger_reason_mask |= mask;
    anti_tamper_update_boot_status();
}


/*!
@brief This function clears the bit location for anti-tamper trigger reason.
*/
void anti_tamper_reason_clr(uint32_t bit_position)
{
    uint16_t mask = (0x1 << bit_position);
    s_anti_tamper_ctx.trigger_reason_mask &= ~mask;
}

STATIC void clear_anti_tamper_table(void)
{
    s_anti_tamper_ctx.table.anti_tamper_cfg.word = 0;
    //Frequency configuration
    s_anti_tamper_ctx.table.frequency_cfg.word = 0;
    //Temperature configuration
    s_anti_tamper_ctx.table.temperature_cfg.word = 0;
    //Voltage configurationa
    s_anti_tamper_ctx.table.voltage_cfg.word = 0;

    s_anti_tamper_ctx.valid = false;

    s_anti_tamper_ctx.upr_temp_signed = 0;
    s_anti_tamper_ctx.lwr_temp_signed = 0;

    s_anti_tamper_ctx.num_vadc_ch = NUM_VADC_MONITOR_CH;
    s_anti_tamper_ctx.vadc_ch_mask = 0;

    s_anti_tamper_ctx.trigger_reason_mask = 0;

    s_anti_tamper_ctx.init_status = 0;
    s_anti_tamper_ctx.enable_status = 0;

    s_anti_tamper_ctx.zerorization_status = 0;
    s_anti_tamper_ctx.zerorization_mask = 0;
}

/*!
This function returns the state of the frequency tamper detection enable.
If s_anti_tamper_ctx is not valid (the value has not being initialized)
ATPR_DISABLE will be returned

@return Returns frequency tamper detection.
 */
atpr_enable_t anti_tamper_get_freq_det_enable(void)
{
    //Verify global enable, get_atpr_global_enable verifies tha the table is valid
    if(anti_tamper_get_global_enable() != ATPR_TYPE_INVALID)
    {
        //If the response is enabled check the feature enabling
        return (atpr_enable_t)ATPR_FREQ_DETECTION(s_anti_tamper_ctx.table.frequency_cfg);
    } else {
        return ATPR_DISABLE;
    }
}

/*!
This function returns the frequency range set in the anti-tamper table
Warning: This function should not be used before building the table

@return Returns frequency range set in the anti-tamper table
 */
atpr_freq_t anti_tamper_get_frequency_range(void)
{
    return (atpr_freq_t)GET_ATPR_FREQ_PCT(s_anti_tamper_ctx.table.frequency_cfg);
}

/*!
This function returns the state of the temperature tamper detection enable.
If s_anti_tamper_ctx is not valid (the value has not being initialized)
ATPR_DISABLE will be returned

@return Returns temperature tamper detection.
 */
atpr_enable_t anti_tamper_get_temp_enable(void)
{
    //Verify global enable,  get_atpr_global_enable verifies tha the table is valid
    if(anti_tamper_get_global_enable() != ATPR_TYPE_INVALID)
    {
        //If the response is enabled check the feature enabling
        return (atpr_enable_t)ATPR_TEMP_DETECTION(s_anti_tamper_ctx.table.temperature_cfg);
    }

    return ATPR_DISABLE;
}

/*!
This function returns the state of the voltage tamper , return true if VCCL
or VCCL SDM detection enable. If s_anti_tamper_ctx is not valid
(the value has not being initialized) ATPR_DISABLE will be returned

@return Returns voltage tamper detection.
 */
atpr_enable_t anti_tamper_get_voltage_enable(void)
{
    if (get_atpr_vccl_enable() == ATPR_ENABLE || get_atpr_vccl_sdm_enable() == ATPR_ENABLE)
    {
        return ATPR_ENABLE;
    } else {
        return ATPR_DISABLE;
    }
}

/*!
This function returns the state of the VCCL SDM tamper detection enable.
Warning: This function should not be used before building the table

@return Returns VCCL SDM tamper detection.
 */
atpr_enable_t get_atpr_vccl_sdm_enable(void)
{
    //Verify global enable, get_atpr_global_enable verifies tha the table is valid
    if(anti_tamper_get_global_enable() != ATPR_TYPE_INVALID)
    {
        //If the response is enabled check the feature enabling
        return (atpr_enable_t)ATPR_VCCL_SDM_ENABLE(s_anti_tamper_ctx.table.voltage_cfg);
    }
    else
    {
        return ATPR_DISABLE;
    }
}

/*!
This function returns the state of the VCCL tamper detection enable.
Warning: This function should not be used before building the table

@return Returns VCCL tamper detection.
 */
STATIC atpr_enable_t get_atpr_vccl_enable(void)
{
    //Verify global enable, get_atpr_global_enable verifies tha the table is valid
    if(anti_tamper_get_global_enable() != ATPR_TYPE_INVALID)
    {
        //If the response is enabled check the feature enabling
        return (atpr_enable_t)ATPR_VCCL_ENABLE(s_anti_tamper_ctx.table.voltage_cfg);
    }
    else
    {
        return ATPR_DISABLE;
    }
}

/*!
This function returns the sign extended temperature value.

@return Returns temperature as signed integer.
 */
STATIC int32_t get_temp_sign_extension(uint32_t temp)
{
    int32_t temp_signed;

    if(temp & ATPR_TEMP_NEG_MASK)
    {
        //Negative value, pad for type conversion
        temp_signed = (int32_t)(ATPR_TEMP_NEG_PAD | temp);
    }
    else
    {
        temp_signed = (int32_t)(temp);
    }

    return temp_signed;
}

/*!
This function returns the temperature upper threshold in the anti-tamper table
Warning: This function should not be used before building the table

@return Returns temperature upper threshold in the anti-tamper table
 */
int32_t anti_tamper_get_temp_upr_thold(void)
{
    return s_anti_tamper_ctx.upr_temp_signed;
}

/*!
This function returns the temperature lower threshold in the anti-tamper table
Warning: This function should not be used before building the table

@return Returns temperature lower threshold in the anti-tamper table
 */
int32_t anti_tamper_get_temp_lwr_thold(void)
{
    return s_anti_tamper_ctx.lwr_temp_signed;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//                                                       CLOCK TRIGGER HANDLER
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*!
This function is invoked in the context of the frequency tamper ISR as
a result of frequency tamper detection. 
@return None
 */
void anti_tamper_freq_det_handler(void)
{
    if (anti_tamper_get_freq_det_enable() == ATPR_ENABLE)
    {
        anti_tamper_reason_set(AT_REASON_FREQ_BIT);
#if !defined(BLOCK_LEVEL_TESTS) && !defined(UNIT_TEST)
        post_event_and_phase1_wipe_notification(ALT_SDM_MBOX_CMD_CLEAN_MBOXT_FOR_ANTI_TAMPER);
#endif
    }
}

bool fpga_anti_tamper_detect_enabled(void)
{
    return ((s_anti_tamper_ctx.enable_status & ANTI_TAMPER_INIT_STATUS_FPGA) != 0);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//                                                       FPGA TAMPER DETECTION
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*!
This ISR is triggered as a result of  user detected tamper event.
@param None
@return None
 */
STATIC void anti_tamper_fpga_event_isr(void* context)
{
    if (anti_tamper_get_fpga_enable() == ATPR_ENABLE)
    {
        anti_tamper_reason_set(AT_REASON_FPGA_BIT);
#if !defined(BLOCK_LEVEL_TESTS) && !defined(UNIT_TEST)
        if (post_event_and_phase1_wipe_notification(ALT_SDM_MBOX_CMD_CLEAN_MBOXT_FOR_ANTI_TAMPER) == SDM_SUCCESS)
        {
            // This ISR triggers multiple times in a row.
            // Once we've successfully posted the event, disable the IRQ.
            irq_disable(FPGA_GPIO_4_IRQ_ID);
        }
#endif
    }
}

STATIC sdm_return_t anti_tamper_fpga_detect_init(void)
{
    if (s_anti_tamper_timer == (timer_handle_t)SDM_HANDLE_INVALID)
    {
        // claim timer_2 as the anti_tamper FPGA response timer
        s_anti_tamper_timer = timer_open(TIMER_2);

        if (s_anti_tamper_timer == (timer_handle_t)SDM_HANDLE_INVALID)
        {
            SDM_TRACE_ERROR(TRACE_ANTI_TAMPER_TIMER_INIT_ERROR, __LINE__);
            return SDM_ERROR;
        }
        // register isr for resp done timer
        irq_disable(timer_int_id_get(s_anti_tamper_timer));
        irq_register(timer_int_id_get(s_anti_tamper_timer), anti_tamper_timer_isr, NULL);
        irq_enable(timer_int_id_get(s_anti_tamper_timer));
    }

    // register isr for fpga tamper event input
    // FPGA notifies user detected tamper event via interrupt.
    irq_disable(FPGA_GPIO_4_IRQ_ID);
    irq_register(FPGA_GPIO_4_IRQ_ID, anti_tamper_fpga_event_isr, NULL);

    // register isr for fpga tamper resp done
    // FPGA notifies user logic zerorization done via interrupt.
    irq_disable(FPGA_GPIO_3_IRQ_ID);
    irq_register(FPGA_GPIO_3_IRQ_ID, anti_tamper_fpga_resp_done_isr, NULL);

    // Deassert SDM2FPGA AT EVENT (GPO_11)
    system_control_clr_fpga_gpio(ANTI_TAMPER_SDM2FPGA_AT_EVENT_SET_MSK);

    update_anti_tamper_zerorization_mask(AT_RESPONSE_FPGA_ZERORIZE_MSK);

    anti_tamper_init_status_set(ANTI_TAMPER_INIT_STATUS_FPGA);

    return SDM_SUCCESS;
}

STATIC sdm_return_t anti_tamper_fpga_detect_enable(void)
{
    // When user includes Anti-Tamper detection and response Soft-IP in the design,
    // the FPGA anti-tamper detection enable bit will be set in the global
    // anti-tamper configuration.
    if (anti_tamper_init_status_get() & ANTI_TAMPER_INIT_STATUS_FPGA)
    {
        irq_enable(FPGA_GPIO_4_IRQ_ID);
    }
    else
    {
        return SDM_ERROR;
    }

    anti_tamper_enable_status_set(ANTI_TAMPER_ENABLE_STATUS_FPGA);

    return SDM_SUCCESS;
}

STATIC void anti_tamper_timer_isr(void* context)
{
    // interval timer expired , FPGA did not notify they were done with the zeroization.
    // Disable the resp done interrupt. 
    irq_disable(FPGA_GPIO_3_IRQ_ID);
    timer_stop(s_anti_tamper_timer);
    if (s_anti_tamper_ctx.fpga_zerorize_reqested)
    {

#if !defined(BLOCK_LEVEL_TESTS) && !defined(UNIT_TEST)
        OS_ERR err = OS_ERR_NONE;
        OSFlagPost(&config_flags, CONFIG_OS_FLAGS_AT_FPGA_RESP_IN_PROGRESS, OS_OPT_POST_FLAG_CLR, &err);
#endif
        // timer expired before receiving fpga zerorization done. AT zerorization failure.
    }
}

STATIC void anti_tamper_fpga_resp_done_isr(void* context)
{
    // interrupt should be enabled by fpga zerorize request
    // disable both resp done & timer interrupt
    irq_disable(FPGA_GPIO_3_IRQ_ID);
    irq_disable(timer_int_id_get(s_anti_tamper_timer));

    // Stop FPGA response timer
    timer_stop(s_anti_tamper_timer);
#if !defined(BLOCK_LEVEL_TESTS) && !defined(UNIT_TEST)
    OS_ERR err = OS_ERR_NONE;
    OSFlagPost(&config_flags, CONFIG_OS_FLAGS_AT_FPGA_RESP_IN_PROGRESS, OS_OPT_POST_FLAG_CLR, &err);
#endif

    if (ANTI_TAMPER_FPGA2SDM_AT_ZERO_STAT_GET(system_control_get_fpga_gpio()))
    {
        anti_tamper_zerorization_status_set(AT_RESPONSE_FPGA_ZERORIZE_MSK);
    }
}

/*!
@brief Check current zeroization status against expected status and update associated pin.
@param None
@return None
 */
void anti_tamper_determine_response_result_pin_status(void)
{
    // Will have already assert_tamper_response_result(false) in phase1 at start of wipe,
    // only need to check if it should be set true here.
    if (((s_anti_tamper_ctx.zerorization_status ^ s_anti_tamper_ctx.zerorization_mask) & AT_RESPONSE_ALL_ZERORIZE_MSK) == 0)
    {
        pin_table_assert_tamper_response_result(true);
        anti_tamper_reason_set(TAMPER_ZEROIZE_BIT_POS);
    }
}

/*!
@brief Request FPGA to being zeroization and start a timeout timer for this action
@param None
@return None
 */
void anti_tamper_fpga_zerorize_request(void)
{
    uint32_t period;
    // enable interrupt for fpga at resp done
    irq_enable(FPGA_GPIO_3_IRQ_ID);

    system_control_set_fpga_gpio(ANTI_TAMPER_SDM2FPGA_AT_EVENT_SET_MSK);
    period = ANTI_TAMPER_FPGA_ZERORIZATION_TIMEOUT_MS * (200000000 / 1000);
    // start timer
    timer_start(s_anti_tamper_timer, ALT_TMR_CONTROL_ITO_SET(1) | ALT_TMR_CONTROL_START_SET(1), period);
}

/*!
This function is invoked as part of the AT response flow to update bootstatus register.
@param None
@return None
 */
void anti_tamper_update_boot_status(void)
{
#ifndef BLOCK_LEVEL_TESTS
    // Do not provide ATPR bootstatus when production
    if (system_control_stickybit_get(SDM_CMF_NOT_PROD_DEBUG_STICKY_BIT) == true)
    {
        return;
    }
    // Firmware shall write tamper detection and response status into boot_status register for internal debug purpose.     
    ALT_JTAG_BOOT_BOOTSTATUS_t *pjtag_regs = (ALT_JTAG_BOOT_BOOTSTATUS_t*)(ALT_JTAG_BOOT_BOOTSTATUS_ADDR);

    // Set JTAG bootstatus based on tamper reason we've been tracking
    // Also, per HSD:1707153321 we track nStatus, tamper detect, and tamper zeroization here
    // Map of bootstatus register after ATPR response:
    // [31:16] - Reserved, ATPR response writes these as 0xF00F
    // [15] - Device killed
    // [14] - nStatus pin state (new)
    // [13] - Tamper detect pin state (new)
    // [12] - Tamper response status (Zeroization) pin state (new)
    // [11:4] - Reserved
    // [3:0] - ATPR trigger reason bits
    //     [3] - FPGA
    //     [2] - Voltage
    //     [1] - Temperature
    //     [0] - Frequency
    pjtag_regs->bootsts = ERR_ANTI_TAMPER_REPORT_ERROR |
        (gpio_is_pin_deasserted(GPIO_PIN_NSTATUS) << NSTATUS_BIT_POS) |
        anti_tamper_reason_get();
#endif        
}

/*!
This function is invoked to determine if kill bit associated to the trigger is set.
@param None
@return true if kill bit for the particular trigger is set. 
 */
static bool is_anti_tamper_kill_reason_set(void)
{
    uint32_t triggers = ANTI_TAMPER_TRIGGER_REASON_GET(anti_tamper_reason_get());
    uint32_t enables = GET_ATPR_GLOBAL_KILL_ENABLES(s_anti_tamper_ctx.table.anti_tamper_cfg);

    return ((triggers & enables) != 0);
}

/*!
In self-kill response, after all the regular response handling done and anti-tamper event reported, firmware will blow fuses to 
result into BootROM Checksum fail to disrupt bootROM flow and result in permanently locking down the device
@param None
@return None. 
 */
void anti_tamper_disable_device()
{
    atpr_response_type_t resp_category = anti_tamper_get_global_enable();

    bool resp_cat_ii_to_iv = (resp_category >= ATPR_TYPE_II) && (resp_category <= ATPR_TYPE_IV);
    bool kill_device = ATPR_GLOBAL_KILL_ENABLED(s_anti_tamper_ctx.table.anti_tamper_cfg)
                        && is_permit_self_kill_fuse_blown()
                        && is_anti_tamper_kill_reason_set()
                        && resp_cat_ii_to_iv;
    if (kill_device)
    {
        uint32_t virtual_kill = persistent_get_virtual_kill()? 1:0;

        // cancel all the PSG keys by blowing all the bits in row 27 to row 30 on ND
        if (altera_sdm_efuse_cancel_all_public_key(virtual_kill) != SDM_SUCCESS)
        {
            // Log failure
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return;
        }
        // Blow "Device killed" fuse, then ROM code will stop in dead loop
        if (altera_sdm_efuse_device_kill_program(virtual_kill) != SDM_SUCCESS)
        {
            // Log failure
            SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
            return;
        }
        anti_tamper_reason_set(DEVICE_KILLED_BIT_POS);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//                                                       KEY ZEROIZATION
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void bbram_key_cleaning(void)
{
    bbram_handle_t bbram_handle = bbram_open();
    if (bbram_handle == (bbram_handle_t)SDM_HANDLE_INVALID)
    {
        SDM_TRACE_ERROR(TRACE_ERROR, __LINE__);
        return;
    }

    if (bbram_key_clean(bbram_handle) != SDM_SUCCESS)
    {
         SDM_TRACE_ERROR(TRACE_BBRAM_KEY_REG_CLEAN_FAILED, __LINE__);
    }

    bbram_close(bbram_handle); // Close the handle or clean confirm will fail.
}
/*
static void bbram_key_zeroization_check(crypto_context_t* crypto_ctx)
{
    if (cmf_config_aes_keysource_clean_confirm(crypto_ctx, CMF_KEY_TYPE_BBRAM, CMF_INVALID_KEY_ID) == SDM_SUCCESS)
    {
        anti_tamper_zerorization_status_set(AT_RESPONSE_BBRAM_KEY_ZERORIZE_MSK);
    }
    else
    {
        SDM_TRACE_ERROR(TRACE_BBRAM_KEY_ZERORIZE_FAILED, __LINE__);
    }
}
*/
static void ukv_key_reg_cleaning(void)
{
    // UKV key reg clean and confirm
    if (ukv_clean_key_reg() == SDM_SUCCESS)
    {
        anti_tamper_zerorization_status_set(AT_RESPONSE_UKV_KEYREG_ZERORIZE_MSK);
    }
    else
    {
        SDM_TRACE_ERROR(TRACE_UKV_KEY_REG_CLEAN_FAILED, __LINE__);
    }
}

static void ukv_key_cleaning(void)
{
    // Issue UKV key clean
    if (ukv_clear_all_keys() != KEYVAULT_OPERATION_SUCCESS)
    {
        SDM_TRACE_ERROR(TRACE_UKV_KEY_RAM_CLEAN_FAILED, __LINE__);
    }
    else
    {
        if (anti_tamper_get_global_enable() == ATPR_TYPE_II)
        {
            // AT2 only cares that we cleared keys, doesn't do zeroization check.
            // Set status here so RESPONSE_DONE pin can get asserted later.
            anti_tamper_zerorization_status_set(AT_RESPONSE_UKV_KEYRAM_ZERORIZE_MSK);
        }
    }
}

static void ukv_key_zeroization_check(crypto_context_t* crypto_ctx)
{
    uint32_t ukv_failed_slot_count = 0;
    for (uint32_t ind=0; ind<UKV_NUM_KEY_SLOTS; ind++)
    {
        if (cmf_config_aes_keysource_clean_confirm(crypto_ctx, CMF_KEY_TYPE_UKV, (cmf_key_id_t)ind) != SDM_SUCCESS)
        {
            ukv_failed_slot_count++;
            SDM_TRACE_ERROR(TRACE_UKV_KEY_ZERORIZE_FAILED, ind);
            SDM_TRACE_ERROR(TRACE_UKV_KEY_ZERORIZE_FAILED, ukv_failed_slot_count);
        }
    }
    if (ukv_failed_slot_count == 0)
    {
        SDM_TRACE_ERROR(TRACE_UKV_KEY_CLEAN_CONFIRMED, __LINE__);
        anti_tamper_zerorization_status_set(AT_RESPONSE_UKV_KEYRAM_ZERORIZE_MSK);
    }
}

static void efuse_key_reg_cleaning(void)
{
    // Issue EFUSE key register clean
    if (hal_efuse_aes_reg_clean() == SDM_SUCCESS)
    {
        anti_tamper_zerorization_status_set(AT_RESPONSE_EFUSE_KEY_ZERORIZE_MSK);
    }
    else
    {
        SDM_TRACE_ERROR(TRACE_EFUSE_KEYREG_CLEAN_FAILED,__LINE__);
    }
}

// initialize hw engines we will use for key zeroization checks
static sdm_return_t crypto_setup_for_key_zeroization(crypto_context_t* crypto_ctx)
{
    sdm_return_t status = SDM_ERROR;
    sha_handle_t sha_handle = (sha_handle_t)SDM_HANDLE_INVALID;
    dma_handle_t dma_handle = (dma_handle_t)SDM_HANDLE_INVALID;
    pkc_handle_t pkc_handle = (pkc_handle_t)SDM_HANDLE_INVALID;
    in_buf_handle_t in_buf_handle = (in_buf_handle_t)SDM_HANDLE_INVALID;

    sha_handle = sha_open();
    dma_handle = dma_open(DMA_SRC_SDM,DMA_DEST_SDM);
    pkc_handle = pkc_open();
    in_buf_handle = in_buf_open();

    do
    {
        // If any of the handles is invalid, this function will return error.
        if (crypto_context_create(crypto_ctx, in_buf_handle, dma_handle, sha_handle, pkc_handle) != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_BBRAM_KEY_ZERORIZE_FAILED, __LINE__);
            break;
        }

        if (in_buf_crypto_enable_set(in_buf_handle, IN_BUF_CRYPTO_AES) != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_BBRAM_KEY_ZERORIZE_FAILED, __LINE__);
            break;
        }

        // Init Key Manager, APIs in this block are called by keys fifo init function
        cmf_km_init();

        cmf_config_aes_init();

        // init the input buffer
        status = in_buf_reset(in_buf_handle);
        if (status != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_BBRAM_KEY_ZERORIZE_FAILED, __LINE__);
            break;
        }

        //configure fifo
        fifo_cfg_t inbuf_cfg = { 0, 1024 };
        status = in_buf_fifo_cfg(in_buf_handle, &inbuf_cfg, 1);
        if (status != SDM_SUCCESS)
        {
            SDM_TRACE_ERROR(TRACE_BBRAM_KEY_ZERORIZE_FAILED, __LINE__);
            break;
        }

        // Initialize the AES device driver
        cmf_aes_init();
    } while(0);

    if (status != SDM_SUCCESS)
    {
        // Cleanup on failure
        crypto_context_release(crypto_ctx);
    }

    return status;
}

/*!
@brief Perform anti-tamper key cleaning based on global AT type.
@return None
*/
void anti_tamper_key_cleaning(void)
{
    atpr_response_type_t global_enable = anti_tamper_get_global_enable();

    // HSD:1707054978
    // Clean AES key register first
    // Next to issue the clean command (HW register) first for both UKV and BBRAM
    // Then when they are done, start the zerorization check
    // This is to clean the key contents as quickly as we can. Because zerorization check takes time

    if (global_enable > ATPR_TYPE_I)
    {
        // Clean aeskey source registers
        ukv_key_reg_cleaning();
        efuse_key_reg_cleaning();
    }

    // Kick off key cleaning
    // Category IV: Category III and BBRAM Key Zeroization 
    // CMF shall perform all actions defined in Category III, plus the below functions.  
    // Clean BBRAM Key 
	// Verify BBRAM Key is zeroized
    switch(global_enable)
    {
        case ATPR_TYPE_IV:
            bbram_key_cleaning();
            __attribute__((fallthrough));
        case ATPR_TYPE_III:
        case ATPR_TYPE_II:
            ukv_key_cleaning();
            break;
        default:
            break;
    }
}

/*!
@brief Perform anti-tamper key zeroization checks based on global AT type.
@return None
*/
void anti_tamper_key_zeroization(void)
{
    atpr_response_type_t global_enable = anti_tamper_get_global_enable();

    if (global_enable > ATPR_TYPE_II)
    {
        // Key zeroization checks
        crypto_context_t crypto_ctx;
        // This is invokved during wipe. The crypto state needs to be setup 
        // to a quiescent state or zeroization check will timeout. 
        if (crypto_setup_for_key_zeroization(&crypto_ctx) != SDM_SUCCESS)
        {
            // Cannot run zeroization checks if crypto setup fails
            return;
        }
        switch(global_enable)
        {
            case ATPR_TYPE_IV:
                bbram_key_zeroization_check(&crypto_ctx);
                __attribute__((fallthrough));
            case ATPR_TYPE_III:
                ukv_key_zeroization_check(&crypto_ctx);
                break;
            default:
                break;
        }
        // Don't forget to close crypto handles!
        crypto_context_release(&crypto_ctx);
    }
}

/*! @} */

#endif
