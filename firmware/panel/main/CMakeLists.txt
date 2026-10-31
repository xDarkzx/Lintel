idf_component_register(SRCS main.cpp keypad_ui.cpp
                       INCLUDE_DIRS .
                       REQUIRES lintel_core lintel_platform
                       PRIV_REQUIRES nvs_flash esp_netif esp_event esp_wifi esp_timer console lwip
                                     espressif__esp32_p4_function_ev_board)
idf_component_get_property(LVGL_LIB lvgl__lvgl COMPONENT_LIB)
target_compile_options(${LVGL_LIB} PRIVATE -DLV_LVGL_H_INCLUDE_SIMPLE)
