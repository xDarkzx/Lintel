# No REQUIRES list: like infinity_face, main sees every component, which the
# camera stack (esp_video, esp_cam_sensor, JPEG driver) needs.
file(GLOB FONT_SRCS ${CMAKE_CURRENT_LIST_DIR}/fonts/*.c)
idf_component_register(SRCS main.cpp keypad_ui.cpp usb_link.cpp camera.cpp identity.cpp app_video.c ${FONT_SRCS}
                       INCLUDE_DIRS .)
idf_component_get_property(LVGL_LIB lvgl__lvgl COMPONENT_LIB)
target_compile_options(${LVGL_LIB} PRIVATE -DLV_LVGL_H_INCLUDE_SIMPLE)
