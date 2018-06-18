# SK Telecom Smart Home for Mico OS

This project is a demonstration firmware for [MXCHIP](http://en.mxchip.com) IoT module connectecd to [SK Telecom's Smart Home](https://www.sktsmarthome.com) Service.

It is developed on [MiCO](http://developer.mxchip.com) Internet Connectivity OS.


## Developement Status

- add user configuration in flash
- implement initial pairing procedure with smartphone


## ToDo 

- implement GMPP protocol
- Sample code control port and notify events

MiCO provide EasyLink that is proprietary ZeroConf of MXCHIP. With EasyLink, you only need to input passpharase of AP manually during device paring procedure. It means transfer current SSID of a smartphone to a device automatically. 
It should be adopted in SK smartphone app before commercial lanuch. ([Youtube Demo](https://www.youtube.com/watch?v=ut0SI5-yZaU))


## How to Build

First you need [MiCO](http://developer.mxchip.com) development tools. 

- Download MiCoder Tools (openocd, arm-none-eabi cross compiler, JLink driver, compile utility)
  - [MiCoder Tools for Windows](http://7xnbsm.com1.z0.glb.clouddn.com/MiCoder_v1.1.Win32.zip)
  - [MiCoder Tools for macOS](http://7xnbsm.com1.z0.glb.clouddn.com/MiCoder_v1.1.macOS.tar.gz)
  - [MiCoder Tools for Linux](http://7xnbsm.com1.z0.glb.clouddn.com/MiCoder_v1.1.Linux.tar.gz)
- Install MiCo Cube (Python-based MiCO development workflow script like [Arm Mbed CLI](https://os.mbed.com/docs/v5.8/tools/arm-mbed-cli.html))

```shell
$ pip install mico-cube
```



Download the all related source code and library using mico-cube.

```shell
$ mico import https://github.com/humminglab/skt-iot-demo.git -v -vv
```



Build and Run

- Set the MiCoder tools path

```shell
$ mico config --global MICODER ~/MiCO_SDK/MiCO/MiCoder
```

- Compile, download and run

```shell
$ mico make skdemo@MK3080B@MOC download run JTAG=jlink_swd
```
