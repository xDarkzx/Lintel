cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../../components
    ${CMAKE_CURRENT_LIST_DIR}/../../third_party)
set(EXCLUDE_COMPONENTS lintel_radio)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
add_compile_options(-Wno-format -Wno-ignored-qualifiers)
project(lintel_panel)
