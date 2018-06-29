/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"

#include "smarthome_conf.h"
#include "omp.h"

#define smarthome_log(format, ...)  custom_log("main", format, ##__VA_ARGS__)

typedef struct {
    int amount_of_electricity_used;
    int power;
    int mode;
    int humidity_hope;
    int humidity;
    int airflow;
    int plasma;
    int child_lock;
    int full_water_bucket;
} device_state;

static device_state _state = {
    .amount_of_electricity_used = 0,
    .power = 1,
    .mode = 1,
    .humidity_hope = 60,
    .humidity = 40,
    .airflow = 1,
    .plasma = 0,
    .child_lock = 0,
    .full_water_bucket = 1
};
    
static void fill_periodic_report( json_object *msg )
{
    time_t now;
    char buf[10];
    char *p;

    now = time(NULL);
    sprintf(buf, "%ld", now);
    json_object_object_add(msg, "work_time", json_object_new_string(buf));

    sprintf(buf, "%d", _state.amount_of_electricity_used);
    json_object_object_add(msg, "amount_of_electricity_used", json_object_new_string(buf));

    p = (_state.mode) ? "on" : "off";
    json_object_object_add(msg, "power", json_object_new_string(p));
    
    sprintf(buf, "%02d", _state.mode);
    json_object_object_add(msg, "mode", json_object_new_string(buf));

    sprintf(buf, "%d", _state.humidity_hope);
    json_object_object_add(msg, "humidity_hope", json_object_new_string(buf));
    
    sprintf(buf, "%d", _state.humidity);
    json_object_object_add(msg, "humidity", json_object_new_string(buf));
    
    sprintf(buf, "%02d", _state.airflow);
    json_object_object_add(msg, "airflow", json_object_new_string(p));
    
    p = (_state.plasma) ? "on" : "off";
    json_object_object_add(msg, "plasma", json_object_new_string(p));

    p = (_state.child_lock) ? "on" : "off";
    json_object_object_add(msg, "child_lock", json_object_new_string(p));

    sprintf(buf, "%02d", _state.full_water_bucket);
    json_object_object_add(msg, "full_water_bucket", json_object_new_string(p));
}

int application_start( void )
{
    /* Start MiCO system functions according to mico_config.h*/
    mico_system_init( mico_system_context_init( smarthome_get_size_user_data() ) );
    smarthome_conf_cli_register();

    /* Output on debug serial port */
    smarthome_log( "Start SmartHome Demo!" );

    if (mico_system_context_get()->micoSystemConfig.configured == allConfigured)
	    omp_client_start( fill_periodic_report );

    /* Trigger MiCO system led available on most MiCOKit */
    while(1)
    {
	MicoGpioOutputTrigger( MICO_SYS_LED );
	mico_thread_sleep(1);
    }
    
}
