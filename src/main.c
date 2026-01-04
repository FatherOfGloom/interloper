#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <dwmapi.h>
#include <assert.h>
#include <shlobj.h>
#include <stdint.h>

#include "vec.h"

typedef struct Slice {
    void* ptr; 
    size_t len;
} Slice;

typedef HWND WindowHandle;

typedef struct Window {
    WindowHandle handle;
    // TODO: arena alloc
    wchar_t file_path[MAX_PATH];
    Slice file_name;
    DWORD file_path_len;
} Window;

typedef struct Windows {
    // TODO: arena alloc
    Window items[128];
    size_t len;
} Windows;

typedef struct StrUtf16 {
    Vec v;
} StrUtf16;

void str_utf16_append(StrUtf16* s, wchar_t* wcstr) {
    vec_append(&s->v, sizeof(wchar_t), wcstr, wcslen(wcstr));
}

StrUtf16 str_utf16_from_slice(Slice wcstr) {
    StrUtf16 s = {0};
    s.v = vec_with_cap(sizeof(wchar_t), wcstr.len + 1);
    vec_append(&s.v, sizeof(wchar_t), wcstr.ptr, wcstr.len);
    return s;
}

typedef struct Context {
    Windows w;
    Vec hotkey_table;
    StrUtf16 appdata_path;
    // TODO: owned temp_arena
} Context; 

Slice extract_file_name_utf16(Slice file_path_utf16) {
    assert(file_path_utf16.len > 0);

    void* ptr = NULL;
    size_t len = 0;
    wchar_t* file_path = file_path_utf16.ptr;

    for (int i = 0; i < file_path_utf16.len; ++i) {
        wchar_t c = file_path[file_path_utf16.len - i - 1];

        if (c == L'\\') {
            ptr = file_path + file_path_utf16.len - i;
            len = i;
            break;
        }
    }

    return (Slice){.ptr = ptr, len = len};
}

void win32_get_exe_file_path(WindowHandle handle, wchar_t* file_path, DWORD* file_path_len) {
    DWORD pid = 0;
    GetWindowThreadProcessId(handle, &pid);

    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);

    QueryFullProcessImageNameW(ph, 0, file_path, file_path_len);

    CloseHandle(ph);
}

int CALLBACK win32_on_enum_windows(WindowHandle handle, LPARAM lParam) {
    Context* ctx = (Context*)lParam;
    Windows* list = &ctx->w;

    // TODO: arena alloc
    Window* w = &list->items[list->len + 1];
    *w = (Window){.handle = handle, .file_path = {0}, .file_path_len = MAX_PATH};

    if (!IsWindowVisible(handle)) {
        return 1;
    }

    if (GetWindow(handle, GW_OWNER)) {
        return 1;
    }

    char title[128] = {0};

    if (GetWindowTextA(handle, title, sizeof(title)) == 0) {
        return 1;
    }

    if (GetWindowLongW(handle, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) {
        return 1;
    }

    HWND hwndTry, hwndWalk = NULL;

    hwndTry = GetAncestor(handle, GA_ROOTOWNER);
    
    while (hwndTry != hwndWalk) {
        hwndWalk = hwndTry;
        hwndTry = GetLastActivePopup(hwndWalk);

        if (IsWindowVisible(hwndTry)) { break; }
    }

    if (hwndWalk != hwndTry) return 1;

    RECT r = {0};
    GetWindowRect(handle, &r);

    if ((r.right - r.left) == 0 || (r.bottom - r.top) == 0) {
        return 1;
    }

    char cn[128];
    GetClassNameA(handle, cn, sizeof(cn));

    if (!strcmp(cn, "Windows.UI.Core.CoreWindow")) { 
        return 1;
    }

    if (!strcmp(cn, "ApplicationFrameWindow")) {
        return 1;
    }

    win32_get_exe_file_path(w->handle, w->file_path, &w->file_path_len);

    if (w->file_path_len > 0) {
        w->file_name = extract_file_name_utf16((Slice){.ptr = w->file_path, .len = w->file_path_len});
    }

    // list->items[list->len++] = w;
    list->len += 1;

    return 1;
}

#define panic(...) do { fprintf(stderr, __VA_ARGS__); exit(0); } while (0)
#define todo(x) panic("panic at f:'%s' l:%d todo!", __FILE__, __LINE__)
#define nonnull(this) __extension__ ({ void* _ptr = (this); if (!_ptr) { panic("f:%s l:%d ERR: %s\n", __FILE__, __LINE__, "unwrap on a null value."); } _ptr; })
#define unwrap(this) __extension__ ({ size_t _this = (this); if (!_this) panic("f:%s l:%d ERR: %s\n", __FILE__, __LINE__, "unwrap failed."); _this; })

#define file_exists(file_path) (access(file_path, F_OK) == 0)
#define file_exists_utf16(file_path)                                             \
    __extension__({                                                              \
        DWORD attr = GetFileAttributesW(file_path);                              \
        (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)); \
    })
#define dir_exists_utf16(dir_path)                                              \
    __extension__({                                                             \
        DWORD attr = GetFileAttributesW(dir_path);                              \
        (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)); \
    })

typedef struct File {
    FILE* handle;
} File;

errno_t file_size(File* file, size_t* size) {
    long saved = ftell(file->handle);
    if (saved < 0) return errno;
    if (fseek(file->handle, 0, SEEK_END) < 0) return errno;
    long result = ftell(file->handle);
    if (result < 0) return errno;
    if (fseek(file->handle, saved, SEEK_SET) < 0) return errno;
    *size = (size_t)result;
    return 0;
}

File file_open(const char* __restrict__ file_name, const char* __restrict__ mode) {
    return (File){.handle = nonnull(fopen(file_name, mode))};
}

File file_open_utf16(const wchar_t* __restrict__ file_name, const wchar_t* __restrict__ mode) {
    return (File){.handle = _wfopen(file_name, mode)};
}

errno_t file_close(File* file) {
    if (file->handle == NULL) return 0;
    errno_t result = fclose(file->handle);
    file->handle = NULL;
    return result;
}

errno_t file_read_exact(File* file, Slice* buffer) {
    assert(buffer->ptr);
    assert(buffer->len);
    fread(buffer->ptr, buffer->len, 1, file->handle);
    if (ferror(file->handle)) return errno;
    return 0;
}

errno_t file_read_all(File* file, Vec* v) {
    size_t size_bytes = 0;
    errno_t err = file_size(file, &size_bytes);
    if (err != 0) return err;
    (void)vec_realloc(v, 1, size_bytes);
    fread(v->items, v->len, 1, file->handle);
    if (ferror(file->handle)) return errno;
    return 0;
}

typedef struct ConfigParserUtf16 {
    wchar_t* text;
    size_t text_len;
    size_t cursor;
} ConfigParserUtf16;

typedef struct ConfigPair {
    Slice key;
    Slice value;
    int is_valid;
} ConfigPair;

ConfigParserUtf16 parser_new(wchar_t* text, size_t text_len) {
    ConfigParserUtf16 p = {0};
    p.text = text; 
    p.text_len = text_len;
    return p;
}

void parser_trim_left(ConfigParserUtf16* p) {
    while (p->cursor < p->text_len && iswspace(p->text[p->cursor])) {
        p->cursor += 1;
    }
}

ConfigPair parser_next(ConfigParserUtf16* p) {
    ConfigPair pair = {0};
    parser_trim_left(p);

    if (p->cursor >= p->text_len) {
        return pair;
    }

    pair.key.ptr = (void*)&p->text[p->cursor];

    while (p->text[p->cursor] != L'\n' && p->cursor < p->text_len) {
        wchar_t c = p->text[p->cursor];

        if (c == L'=') {
            pair.key.len = &p->text[p->cursor] - (wchar_t*)pair.key.ptr;
            p->cursor += 1;
            parser_trim_left(p);

            if (p->cursor < p->text_len) {
                pair.value.ptr = &p->text[p->cursor];
            }
        }

        if (c == L'\n' && pair.value.ptr) {
            pair.value.len = &p->text[p->cursor] - (wchar_t*)pair.key.ptr;

            if (pair.value.len == 1 && p->text[p->cursor] <= 0x7F) {
                pair.is_valid = 1;
            }
        }

        p->cursor += 1;
    }

    return pair;
}

typedef struct HotkeyMapping {
    StrUtf16 file_path;
    Slice file_name;
    wchar_t hotkey;
} HotkeyMapping;

#define HOTKEY_ID_BASE_GOTO 0
#define HOTKEY_ID_BASE_REGISTER 10

int win32_register_hotkey(WindowHandle h, Vec* table, int idx, uint32_t modifiers, uint32_t key) {
    int result = 0;
    result = RegisterHotKey(h, idx, modifiers, key);

    if (result) {
        todo("Add to the table");
    }

    return result;
}

Context global_context = {0};

LRESULT CALLBACK win32_on_main_window(WindowHandle handle, UINT msg, WPARAM wp, LPARAM lp) {
    LRESULT result = 0;
    switch (msg) {
        case WM_HOTKEY: {
            size_t hotkey_id = wp;
            if (hotkey_id >= HOTKEY_ID_BASE_REGISTER && hotkey_id < HOTKEY_ID_BASE_REGISTER + 10) {
                uint32_t mapped_hotkey = '0' + hotkey_id - HOTKEY_ID_BASE_REGISTER;
                WindowHandle foreground_handle = GetForegroundWindow();
                wchar_t fg_file_path[MAX_PATH] = {0};
                DWORD fg_file_path_len = sizeof(fg_file_path);
                win32_get_exe_file_path(foreground_handle, fg_file_path, &fg_file_path_len);

                StrUtf16 owned_file_path = str_utf16_from_slice((Slice){.ptr = fg_file_path, .len = fg_file_path_len});
                Slice owned_file_name_slice = extract_file_name_utf16((Slice){
                    .ptr = owned_file_path.v.items, 
                    .len = owned_file_path.v.len
                });

                for (int i = 0; i < global_context.hotkey_table.len; ++i) {
                    HotkeyMapping mapping = *((HotkeyMapping*)global_context.hotkey_table.items + i);
                    if (mapping.hotkey == mapped_hotkey) {
                        vec_free(&mapping.file_path.v);
                        mapping.file_path = owned_file_path;
                        mapping.file_name = owned_file_name_slice; 
                        return result;
                    }
                }

                if (RegisterHotKey(handle, HOTKEY_ID_BASE_GOTO + global_context.hotkey_table.len, MOD_ALT, mapped_hotkey)) {
                    HotkeyMapping new_mapping = {
                        .file_name = owned_file_name_slice,
                        .file_path = owned_file_path,
                        .hotkey = mapped_hotkey,
                    };
                    wprintf(L"Registered hotkey ALT + %c for '%s'\n", mapped_hotkey, new_mapping.file_path.v.items);

                    vec_push(&global_context.hotkey_table, sizeof(HotkeyMapping), &new_mapping);
                }
            } else if (hotkey_id >= HOTKEY_ID_BASE_GOTO && hotkey_id < HOTKEY_ID_BASE_GOTO + 10) {
                assert(0 <= hotkey_id && hotkey_id < global_context.hotkey_table.len);
                HotkeyMapping mapping = *((HotkeyMapping*)global_context.hotkey_table.items + hotkey_id);

                global_context.w.len = 0;
                EnumWindows(win32_on_enum_windows, (LPARAM)&global_context);

                WindowHandle dst_window_handle = NULL;

                for (int i = 0; i < global_context.w.len; ++i) {
                    Window w = global_context.w.items[i];

                    if (w.file_name.ptr && wcscmp(w.file_name.ptr, mapping.file_name.ptr) == 0) {
                        dst_window_handle = w.handle;
                        break;
                    }
                }

                if (dst_window_handle) {
                    DWORD fgThread = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
                    DWORD targetThread = GetWindowThreadProcessId(dst_window_handle, NULL);

                    AttachThreadInput(fgThread, targetThread, TRUE);

                    SetForegroundWindow(dst_window_handle);
                    BringWindowToTop(dst_window_handle);
                    SetFocus(dst_window_handle);

                    AttachThreadInput(fgThread, targetThread, FALSE);
                } else {
                    todo("Start the program");
                }
            }
        } break;
        default: {
            result = DefWindowProc(handle, msg, wp, lp);
        } break;
    }

    return result;
}

// TODO: rewrite on_enum_windows with arena
// TODO: save mapping to a file
int WINAPI WinMain(HINSTANCE this_instance, HINSTANCE prev_instance, LPSTR command_line, int show_code) {

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = win32_on_main_window;
    wc.hInstance = this_instance;
    wc.lpszClassName = "InterloperHotkeyWindow";
    
    if (!RegisterClassA(&wc)) {
        panic("OOOOPS\n");
    }

    WindowHandle hotkey_window_handle = CreateWindowA(wc.lpszClassName, "", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, this_instance, NULL);

    for (int i = 0; i < 10; ++i) {
        if (!RegisterHotKey(hotkey_window_handle, HOTKEY_ID_BASE_REGISTER + i, MOD_CONTROL | MOD_ALT, '0' + i)) {
            panic("Failed to register Ctrl+Alt+%d\n", i);
        } else {
            wprintf(L"Registered hotkey cstrl + ALT + %c\n", '0' + i);
        }
    }

    wchar_t* path = NULL;
    HRESULT hr = SHGetKnownFolderPath(
        &FOLDERID_RoamingAppData, 
        KF_FLAG_CREATE, 
        NULL, 
        &path
    );

    if (SUCCEEDED(hr)) {
        Vec config_contents = {0};
        str_utf16_append(&global_context.appdata_path, path);
        str_utf16_append(&global_context.appdata_path, L"\\Interloper");
        if (!dir_exists_utf16(global_context.appdata_path.v.items)) {
            int ok = CreateDirectoryW(global_context.appdata_path.v.items, 0);

            if (!ok) {
                panic("Unable to create AppData/Roaming/Interloper subfolder: %d", GetLastError());
            }
        }
        
        str_utf16_append(&global_context.appdata_path, L"\\paths");

        int config_exists = file_exists_utf16(global_context.appdata_path.v.items);
        wprintf(L"APPDATAPATH: %s\n", global_context.appdata_path.v.items);
        File config_file = file_open_utf16(global_context.appdata_path.v.items, L"wb+");

        if (!config_file.handle) {
            perror("fopen");
            return 1;
        } 

        if (config_exists) {
            assert(!file_read_all(&config_file, &config_contents));
        }

        if (config_contents.len > 0) {
            ConfigParserUtf16 p = parser_new(config_contents.items, config_contents.len);
            ConfigPair pair = parser_next(&p);
            int hotkey_id = 0;

            while (pair.is_valid) {
                wchar_t config_value = *(wchar_t*)pair.value.ptr;
                if (RegisterHotKey(hotkey_window_handle, HOTKEY_ID_BASE_GOTO + hotkey_id, MOD_ALT, (unsigned int)config_value)) {
                    HotkeyMapping mapping = {
                        .hotkey = config_value,
                        .file_path = str_utf16_from_slice(pair.key),
                        .file_name = extract_file_name_utf16(pair.key)
                    };
                    vec_push(&global_context.hotkey_table, sizeof(HotkeyMapping), &mapping);
                    printf("CONFIG: Registered hotkey: alt + %s\n", (char[2]){(char)config_value, '\0'});
                    hotkey_id += 1;
                } else {
                    todo("log");
                }

                pair = parser_next(&p);
            }
        }

        vec_free(&config_contents);
        CoTaskMemFree(path);
    } else {
        panic("SHGetKnownFolderPath failed: 0x%08X\n", hr);
    };

    printf("sizeof(Context): %d\n", sizeof(Context));

    MSG msg = {0};

    while (GetMessage(&msg, 0, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}