idf_component_register(SRCS src/lora_link.cpp
                       INCLUDE_DIRS include
                       REQUIRES esp_timer
                       PRIV_REQUIRES jgromes__radiolib)
