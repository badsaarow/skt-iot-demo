/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"

#include "smarthome_conf.h"

#define smarthome_log(format, ...)  custom_log("main", format, ##__VA_ARGS__)

int application_start( void )
{
    /* Start MiCO system functions according to mico_config.h*/
    mico_system_init( mico_system_context_init( smarthome_get_size_user_data() ) );
    smarthome_conf_cli_register();

    /* Output on debug serial port */
    smarthome_log( "Start SmartHome Main!" );

    /* Trigger MiCO system led available on most MiCOKit */
    while(1)
    {
	MicoGpioOutputTrigger( MICO_SYS_LED );
	mico_thread_sleep(1);
    }
}
