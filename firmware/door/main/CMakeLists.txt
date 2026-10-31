idf_component_register(SRCS main.cpp display.cpp console.cpp
                       INCLUDE_DIRS .
                       REQUIRES lintel_core lintel_radio lintel_platform
                       PRIV_REQUIRES esp_driver_gpio esp_driver_spi esp_lcd esp_timer console esp_system)
