# ParkControl License Bypass
A DLL that hooks and bypasses the license verification in ParkControl (a CPU core parking control utility from Bitsum).

## Description
This project contains a source code for a DLL that uses MinHook to intercept and modify the license verification function in ParkControl.exe. The hook forces the function to always return success (1), effectively bypassing the license check.

## Technical Details
The DLL hooks the license handling function in `ParkControl.exe` like this:

```cpp
uint8_t __fastcall hooked_process_license(int64_t request_context, int64_t license_key, char is_activation, int64_t* output_license) {
    std::ostringstream oss;
    oss << "hooked_process_license: Called with license_key=0x" << std::hex << license_key;
    debug_log(oss.str());

    uint8_t v5 = 1; // Force success return value

    int64_t v18 = sub_140002E90();
    if (!v18) {
        sub_140003470(2147500037i64);
        return 0;
    }

    if (output_license) {
        try {
            int64_t* v33 = (int64_t*)((*(int64_t(__fastcall**)(int64_t))(*(uint64_t*)v18 + 24i64))(v18) + 24);
            *output_license = (int64_t)(v33 + 6);
        }
        catch (...) {
            return 0;
        }
    }

    if (request_context) {
        try {
            *(DWORD*)(request_context + 24) = 1;
            *(BYTE*)(request_context + 48) = 0;
        }
        catch (...) {
            return 0;
        }
    }

    // v5 = 1, we are returning a successfull check
    return v5;
}
```

<details>
<summary>View human readable function</summary>

```cpp
// License verification/activation function
// Parameters:
//   a1 - Request context object
//   a2 - License key string
//   a3 - Activation flag (0 = check, 1 = activate)
//   a4 - Output license info
// Returns: Verification status (1 = success, 0 = failure)
int64_t process_license_request(int64_t request_context, 
                               int64_t license_key, 
                               bool is_activation, 
                               uint64_t* output_license) 
{
    uint8_t status = 0; // Default to failure
    __m128i* current_item = (__m128i*)&license_items_table;
    
    // Initialize local variables
    void* item_block[2] = {0};
    void* block_end = 0;
    
    // Process each item in the license items table
    do {
        __m128i item_data = *current_item;
        int item_id = _mm_cvtsi128_si32(item_data);
        uint64_t item_value = _mm_srli_si128(item_data, 8).m128i_u64[0];
        
        // Get string manager instance
        auto string_mgr = get_string_manager();
        if (!string_mgr) {
            throw_error(2147500037);
        }
        
        // Process the item value (either string or numeric)
        if (item_value - 1 > 0xFFFE) { // String handling
            if (item_value) {
                // Calculate string length
                size_t len = 0;
                while (((wchar_t*)(item_value))[len]) len++;
                process_string_value(&string_mgr, item_value, len);
            }
        } else { // Numeric handling
            process_numeric_value(&string_mgr, (uint16_t)item_value);
        }
        
        // Add item to processing block
        if (item_block[1] == block_end) {
            resize_item_block(&item_block, &item_id);
        } else {
            *(int*)item_block[1] = item_id;
            item_block[1] = (char*)item_block[1] + 16;
        }
        
        // Clean up string manager reference
        release_string_manager(string_mgr);
        
        current_item++;
    } while (current_item != (__m128i*)license_items_table_end);

    // Process the collected license items
    int* current_block = (int*)item_block[0];
    int* block_end_ptr = (int*)item_block[1];
    
    if (current_block != block_end_ptr) {
        while (true) {
            int item_id = *current_block;
            auto license_data = get_license_data(*(current_block + 1));
            
            // Prepare activation/check request
            const wchar_t* action = is_activation 
                ? L"edd_action=activate_license" 
                : L"edd_action=check_license";
            
            // Format request URL
            wchar_t* request_url = format_request_url(
                L"%s%s&item_id=%d&license=%s",
                L"https://activate.bitsum.com/?",
                action,
                item_id,
                license_key
            );
            
            // Set up request context
            *(uint8_t*)(request_context + 48) = 0;
            prepare_request(request_context, request_url);
            
            // Execute request and check response
            int response_status = *(int*)(request_context + 24);
            
            if (response_status == 1) { // Success
                if (license_data != (*output_license - 24)) {
                    if (is_valid_license_match(license_data, *output_license - 24)) {
                        *output_license = get_license_value(license_data) + 24;
                        status = 1; // Success
                    } else {
                        update_output_license(output_license, license_data + 6);
                    }
                }
                break;
            }
            else if (response_status == 13) { // Error
                status = 0; // Failure
                break;
            }
            
            // Clean up and move to next item
            release_request_data(request_url);
            release_license_data(license_data);
            
            current_block += 4;
            if (current_block == block_end_ptr) {
                break;
            }
        }
    }
    
    // Clean up item block
    if (item_block[0]) {
        // Release all items in block
        for (auto item = item_block[0]; item != item_block[1]; item += 16) {
            release_license_data(*(item + 1) - 24);
        }
        
        // Free memory
        if (is_heap_block(item_block[0])) {
            free(*(item_block[0] - 1));
        } else {
            free(item_block[0]);
        }
    }
    
    return status;
}
```
</details>

<details>
<summary>View original function</summary>

```cpp
__int64 __fastcall sub_140004B80(__int64 a1, __int64 a2, char a3, _QWORD *a4)
{
  unsigned __int8 v5; // r13
  __m128i *v6; // rdi
  __m128i v7; // xmm6
  __int64 v8; // rax
  unsigned __int64 v9; // xmm6_8
  __int64 v10; // r8
  _QWORD *v11; // rdx
  volatile signed __int32 *v12; // rdx
  int *v13; // rsi
  int *v14; // r15
  int v15; // ebx
  volatile signed __int32 *v16; // rdi
  volatile signed __int32 *v17; // r14
  __int64 v18; // rax
  const wchar_t *v19; // r9
  __int64 v20; // rbx
  int v21; // eax
  _QWORD *v22; // rbx
  _QWORD *v23; // rdi
  volatile signed __int32 *v24; // rdx
  void *v25; // rbx
  volatile signed __int32 *v27; // rsi
  __int64 v28; // rbx
  volatile signed __int32 *v29; // rsi
  __int64 v30; // rbx
  volatile signed __int32 *v31; // rdx
  __int64 v32; // [rsp+20h] [rbp-50h]
  __int64 *v33; // [rsp+30h] [rbp-40h] BYREF
  int v34; // [rsp+38h] [rbp-38h] BYREF
  volatile signed __int32 *v35; // [rsp+40h] [rbp-30h] BYREF
  void *Block[2]; // [rsp+48h] [rbp-28h] BYREF
  void *v37; // [rsp+58h] [rbp-18h]

  v5 = 0;
  *(_OWORD *)Block = 0i64;
  v37 = 0i64;
  v6 = (__m128i *)&unk_140078560;
  do
  {
    v7 = *v6;
    v34 = _mm_cvtsi128_si32(*v6);
    v33 = (__int64 *)&v35;
    v8 = sub_140002E90();
    if ( !v8 )
      sub_140003470(2147500037i64);
    v35 = (volatile signed __int32 *)((*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v8 + 24i64))(v8) + 24);
    v9 = _mm_srli_si128(v7, 8).m128i_u64[0];
    if ( v9 - 1 > 0xFFFE )
    {
      if ( v9 )
      {
        v10 = -1i64;
        do
          ++v10;
        while ( *(_WORD *)(v9 + 2 * v10) );
      }
      sub_1400034D0(&v35, v9);
    }
    else
    {
      sub_140003040(&v35, (unsigned __int16)v9);
    }
    v11 = Block[1];
    if ( Block[1] == v37 )
    {
      sub_140006A40(Block, Block[1], &v34);
    }
    else
    {
      *(_DWORD *)Block[1] = v34;
      v33 = v11 + 1;
      v11[1] = sub_140002A30(v35 - 6) + 24;
      Block[1] = (char *)Block[1] + 16;
    }
    v12 = v35 - 6;
    if ( _InterlockedExchangeAdd(v35 - 2, 0xFFFFFFFF) <= 1 )
      (*(void (__fastcall **)(_QWORD))(**(_QWORD **)v12 + 8i64))(*(_QWORD *)v12);
    ++v6;
  }
  while ( v6 != (__m128i *)off_140078580 );
  v13 = (int *)Block[0];
  v14 = (int *)Block[1];
  if ( Block[0] != Block[1] )
  {
    while ( 1 )
    {
      v15 = *v13;
      v34 = *v13;
      v16 = (volatile signed __int32 *)sub_140002A30(*((_QWORD *)v13 + 1) - 24i64);
      v17 = v16 + 6;
      v35 = v16 + 6;
      v18 = sub_140002E90();
      if ( !v18 )
        sub_140003470(2147500037i64);
      v33 = (__int64 *)((*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v18 + 24i64))(v18) + 24);
      v19 = L"edd_action=activate_license";
      if ( a3 )
        v19 = L"edd_action=check_license";
      LODWORD(v32) = v15;
      sub_1400074F0(&v33, L"%s%s&item_id=%d&license=%s", L"https://activate.bitsum.com/?", v19, v32, a2);
      *(_BYTE *)(a1 + 48) = 0;
      v20 = (__int64)v33;
      sub_140005450(a1, v33);
      v21 = *(_DWORD *)(a1 + 24);
      if ( v21 == 1 )
        break;
      if ( v21 == 13 )
      {
        v27 = (volatile signed __int32 *)(*a4 - 24i64);
        if ( v16 != v27 )
        {
          if ( *((int *)v27 + 4) >= 0 && *(_QWORD *)v16 == *(_QWORD *)v27 )
          {
            v28 = sub_140002A30(v16);
            if ( _InterlockedExchangeAdd(v27 + 4, 0xFFFFFFFF) <= 1 )
              (*(void (__fastcall **)(_QWORD, volatile signed __int32 *))(**(_QWORD **)v27 + 8i64))(*(_QWORD *)v27, v27);
            *a4 = v28 + 24;
            v20 = (__int64)v33;
            v5 = 0;
            goto LABEL_51;
          }
          sub_1400034D0(a4, v17);
        }
        v5 = 0;
        goto LABEL_51;
      }
      if ( _InterlockedExchangeAdd((volatile signed __int32 *)(v20 - 24 + 16), 0xFFFFFFFF) <= 1 )
        (*(void (__fastcall **)(_QWORD))(**(_QWORD **)(v20 - 24) + 8i64))(*(_QWORD *)(v20 - 24));
      if ( _InterlockedExchangeAdd(v16 + 4, 0xFFFFFFFF) <= 1 )
        (*(void (__fastcall **)(_QWORD, volatile signed __int32 *))(**(_QWORD **)v16 + 8i64))(*(_QWORD *)v16, v16);
      v13 += 4;
      if ( v13 == v14 )
        goto LABEL_26;
    }
    v29 = (volatile signed __int32 *)(*a4 - 24i64);
    if ( v16 != v29 )
    {
      if ( *((int *)v29 + 4) >= 0 && *(_QWORD *)v16 == *(_QWORD *)v29 )
      {
        v30 = sub_140002A30(v16);
        if ( _InterlockedExchangeAdd(v29 + 4, 0xFFFFFFFF) <= 1 )
          (*(void (__fastcall **)(_QWORD, volatile signed __int32 *))(**(_QWORD **)v29 + 8i64))(*(_QWORD *)v29, v29);
        *a4 = v30 + 24;
        v20 = (__int64)v33;
      }
      else
      {
        sub_1400034D0(a4, v17);
      }
    }
    v5 = 1;
LABEL_51:
    if ( _InterlockedExchangeAdd((volatile signed __int32 *)(v20 - 24 + 16), 0xFFFFFFFF) <= 1 )
      (*(void (__fastcall **)(_QWORD))(**(_QWORD **)(v20 - 24) + 8i64))(*(_QWORD *)(v20 - 24));
    v31 = v35 - 6;
    if ( _InterlockedExchangeAdd(v35 - 2, 0xFFFFFFFF) <= 1 )
      (*(void (__fastcall **)(_QWORD))(**(_QWORD **)v31 + 8i64))(*(_QWORD *)v31);
  }
LABEL_26:
  v22 = Block[0];
  if ( Block[0] )
  {
    v23 = Block[1];
    if ( Block[0] != Block[1] )
    {
      do
      {
        v24 = (volatile signed __int32 *)(v22[1] - 24i64);
        if ( _InterlockedExchangeAdd(v24 + 4, 0xFFFFFFFF) <= 1 )
          (*(void (__fastcall **)(_QWORD))(**(_QWORD **)v24 + 8i64))(*(_QWORD *)v24);
        v22 += 2;
      }
      while ( v22 != v23 );
    }
    v25 = Block[0];
    if ( (((unsigned __int64)v37 - (unsigned __int64)Block[0]) & 0xFFFFFFFFFFFFFFF0ui64) >= 0x1000 )
    {
      v25 = (void *)*((_QWORD *)Block[0] - 1);
      if ( (unsigned __int64)(Block[0] - v25 - 8) > 0x1F )
        invalid_parameter_noinfo_noreturn();
    }
    j_j_free(v25);
  }
  return v5;
}
```
</details>

# Updating the signatures
1. Launch IDA 64bit.
2. Load in `ParkControl.exe`.
3. Press `ALT+T`.
4. In the search box, enter: `%s%s&item_id=%d&license=%s` and find our function.
5. Use `SigMakerEx` plugin to generate the pattern for the main function.
6. Do the same for the other 2 subs, just look at the disassembly and use the plugin on them too.
7. Convert the signatures from IDA style to code style.
8. Adjust the masks of the signatures.

```cpp
namespace {
    // Signature for sub_140004B80 (main function)
    // You can find this via the tutorial above, the tutorial also works for signatures below
    const uint8_t k_process_license_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x20, 0x44 };
    const uint8_t k_process_license_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const size_t k_process_license_pattern_size = sizeof(k_process_license_pattern);

    // Signature for sub_140002E90
    // Inside the original function you found, look for this sub and generate a signature for it
    const uint8_t k_sub_140002E90_pattern[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x65 };
    const uint8_t k_sub_140002E90_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const size_t k_sub_140002E90_pattern_size = sizeof(k_sub_140002E90_pattern);

    // Signature for sub_140003470
    // Same goes here, just locate this stub and generate a signature for it too
    const uint8_t k_sub_140003470_pattern[] = { 0x48, 0x83, 0xEC, 0x28, 0x8B, 0xD1 };
    const uint8_t k_sub_140003470_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const size_t k_sub_140003470_pattern_size = sizeof(k_sub_140003470_pattern);
}
```

# Usage
After successful injection, you should be able to activate the license in ParkControl.

The hook:
- Intercepts license activation and verification requests
- Forces all requests to return as successful
- Maintains original program functionality while bypassing restrictions
