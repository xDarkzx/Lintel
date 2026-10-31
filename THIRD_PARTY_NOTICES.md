# Third-party notices

Lintel's own code is licensed under [LICENSE](LICENSE) (FSL-1.1-ALv2). The
components below are included in this repository under their own licences,
which continue to apply to them.

| Component | Where | Licence |
|---|---|---|
| ESP32-P4 Function EV Board BSP (Espressif) | `third_party/espressif__esp32_p4_function_ev_board` | Apache-2.0, [LICENSE](third_party/espressif__esp32_p4_function_ev_board/LICENSE) |
| ST7701 LCD driver (Espressif) | `third_party/espressif__esp_lcd_st7701` | Apache-2.0, [license.txt](third_party/espressif__esp_lcd_st7701/license.txt) |
| esp_cam_sensor (Espressif) | `firmware/panel/components/espressif__esp_cam_sensor` | Apache-2.0, [LICENSE](firmware/panel/components/espressif__esp_cam_sensor/LICENSE) |
| Inter typeface (The Inter Project Authors) | `server/lintel_server/static/fonts`, `firmware/panel/main/fonts/inter_*.c` | SIL Open Font License 1.1, [licenses/Inter-OFL-1.1.txt](licenses/Inter-OFL-1.1.txt) |
| Silent-Face anti-spoofing models (Minivision), converted to ONNX | `server/antispoof` | Apache-2.0, [LICENSE](server/antispoof/LICENSE-Silent-Face-Anti-Spoofing.txt) |
| Tabler Icons (Paweł Kuna) | `server/lintel_server/static/icons.svg`, `firmware/panel/main/fonts/icons_*.c` | MIT, [licenses/Tabler-Icons-MIT.txt](licenses/Tabler-Icons-MIT.txt) |

Dependencies fetched at build time (ESP-IDF components listed in
`firmware/*/dependencies.lock`, Python packages in `server/requirements.txt`,
and the OpenCV YuNet, SFace and YOLOX-S models downloaded by `server/Dockerfile`) are
not redistributed here and remain under their authors' licences.
