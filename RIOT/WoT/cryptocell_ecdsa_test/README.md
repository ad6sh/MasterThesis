### About

This application can be used to measure processing time, energy consumption, stack size and memory usage of the hardware accelerated ECDSA operation using the CryptoCell module on the nrf52840dk and the cryptocell library.

### Options
This application runs on a Nordic nrf52840dk board.

#### Energy Consumption
- Set TEST_ENERGY=1 when building the application.
- For further information, please refer to [section-5](../../section-5/README.md).

#### Stack Size
- Set TEST_STACK=1 when building the application.
- Minimal application prints size of used stack at the end of the program.

#### Firmware Size
- Set TEST_MEM=1 when compiling the application.
- The binary can be analyzed with common tools such as `readelf`.