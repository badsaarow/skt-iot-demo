/*
 * Copyright (c) 2018 HummingLab.io
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include "mico.h"

#include "smarthome_conf.h"
#include "smarthome.h"
#include "micokit_ext.h"

#define smarthome_log(format, ...)  custom_log("main", format, ##__VA_ARGS__)

typedef struct {
    int amount_of_electricity_used;
    int power;
    int mode;
    int humidity_hope;
    int humidity;
    int temperature;
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
    .humidity = 0,
    .temperature = 0,
    .airflow = 1,
    .plasma = 0,
    .child_lock = 0,
    .full_water_bucket = 1
};

static void update_led(void)
{
    char buf[30];
    char* power;

    if (_state.power) {
	switch (_state.mode) {
	case 1: power = "AUTO"; break;
	case 2: power = " MAN"; break;
	default:
	case 6: power = "CONT"; break;
	}
    } else {
	power = " OFF";
    }
    
    sprintf(buf, "%4s %3s %2s %3s", power, _state.airflow ? "MAX" : "MIN",
	    _state.plasma ? "PL" : "  ", _state.child_lock ? "CH" : "  ");
    OLED_ShowString(OLED_DISPLAY_COLUMN_START, OLED_DISPLAY_ROW_3, buf);

    sprintf(buf, "T:%2d%% C:%2d%% %2dC", _state.humidity_hope, _state.humidity, _state.temperature);
    OLED_ShowString(OLED_DISPLAY_COLUMN_START, OLED_DISPLAY_ROW_4, buf);
}

static void changed_power(void)
{
    if (_state.power) {
	switch (_state.mode) {
	case 1:
	    rgb_led_open(0x20, 0, 0);
	    break;
	case 2:
	    rgb_led_open(0, 0x20, 0);
	    break;
	default:
	case 6:
	    rgb_led_open(0, 0, 0x20);
	    break;
	}
    } else {
	rgb_led_open(0, 0, 0);
    }    
}

void user_key1_clicked_callback( void )
{
    _state.power = !_state.power;
    changed_power();
    omp_trigger_event();
}

void user_key2_clicked_callback( void )
{
    switch(_state.mode) {
    case 1:
	_state.mode = 2;
	break;
    case 2:
	_state.mode = 6;
	break;
    default:
    case 6:
	_state.mode = 1;
	break;
    }
    changed_power();
    omp_trigger_event();
}

static void reply_control_process( const char *cmd, const char* value)
{
    if( strcmp( cmd, "power" ) == 0 ) {
	_state.power = strcmp(value, "on") == 0 ? 1 : 0;
	changed_power();
    }else if( strcmp( cmd, "mode" ) == 0 ) {
	_state.mode = atoi(value);
	changed_power();
    }else if( strcmp( cmd, "humidity_hope" ) == 0 ) {
	_state.humidity_hope = atoi(value);
    }else if( strcmp( cmd, "airflow" ) == 0 ) {
	_state.airflow = atoi(value);
    }else if( strcmp( cmd, "plasma" ) == 0 ) {
	_state.plasma = strcmp(value, "on") == 0 ? 1 : 0;
    }else if( strcmp( cmd, "child_lock" ) == 0 ) {
	_state.child_lock = strcmp(value, "on") == 0 ? 1 : 0;
    }
}

static void fill_periodic_report( json_object *msg, omp_report_type_t rtype )
{
    time_t now;
    char buf[10];
    char *p;

    now = time(NULL);
    sprintf(buf, "%ld", now);

    json_object_object_add(msg, "work_time", json_object_new_string(buf));
	
    sprintf(buf, "%d", _state.amount_of_electricity_used);
    json_object_object_add(msg, "amount_of_electricity_used", json_object_new_string(buf));
	
    p = (_state.power) ? "on" : "off";
    json_object_object_add(msg, "power", json_object_new_string(p));

    sprintf(buf, "%02d", _state.mode);
    json_object_object_add(msg, "mode", json_object_new_string(buf));

    sprintf(buf, "%d", _state.humidity_hope);
    json_object_object_add(msg, "humidity_hope", json_object_new_string(buf));
    
    sprintf(buf, "%d", _state.humidity);;
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
    
    OLED_Clear();
    OLED_ShowString(OLED_DISPLAY_COLUMN_START, OLED_DISPLAY_ROW_1, "SKT SmartHome");
    rgb_led_init();
    rgb_led_open(0, 0, 0);  // off
  
    /* Output on debug serial port */
    smarthome_log( "Start SmartHome Demo!" );

    if (mico_system_context_get()->micoSystemConfig.configured == allConfigured) {
	OLED_ShowString(OLED_DISPLAY_COLUMN_START, OLED_DISPLAY_ROW_2, "Normal Mode");
	omp_client_start( fill_periodic_report, reply_control_process );
	changed_power();
	
	while(1)
	{
	    int32_t temperature;
	    uint32_t humidity;
	
	    temp_hum_sensor_read( &temperature,  &humidity );
	    _state.humidity = humidity;
	    _state.temperature = temperature;
	    changed_power();
	    update_led();

	    MicoGpioOutputTrigger( MICO_SYS_LED );
	    mico_thread_sleep(1);
	}
    } else {
	OLED_ShowString(OLED_DISPLAY_COLUMN_START, OLED_DISPLAY_ROW_2, "Pairing Mode");
	while(1)
	{
	    MicoGpioOutputTrigger( MICO_SYS_LED );
	    mico_thread_msleep(250);
	}
    }

    /* Trigger MiCO system led available on most MiCOKit */
    
    /* smarthome_log( "Start SmartHome LED!" ); */
    /* rgb_led_open(0xff, 0, 0xff);  // off */
    

    
}
