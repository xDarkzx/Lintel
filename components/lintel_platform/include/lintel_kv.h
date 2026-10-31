// Small NVS wrapper used by all three firmwares. Everything lives in the
// "lintel" namespace. Keys are short because NVS limits them to 15 chars.
#pragma once

#include <cstddef>
#include <cstdint>

namespace lintel {

bool kv_init();
bool kv_get_u32(const char* key, uint32_t& out);
bool kv_set_u32(const char* key, uint32_t v);
bool kv_get_blob(const char* key, void* out, size_t len);  // exact length required
bool kv_set_blob(const char* key, const void* data, size_t len);
size_t kv_blob_size(const char* key);
bool kv_erase(const char* key);
bool kv_erase_all();

// Parses exactly `len` bytes of hex. Returns false on any other input.
bool parse_hex(const char* s, uint8_t* out, size_t len);

}  // namespace lintel
