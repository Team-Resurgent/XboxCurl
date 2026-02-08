/*
 * Xbox Console Text Renderer Implementation
 * Direct framebuffer text rendering for Xbox
 *
 * Based on Microsoft Xbox SDK patterns for direct surface access
 */

#include "xbox_console.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* 8x8 bitmap font - ASCII 32-127 */
static const unsigned char font_8x8[96][8] = {
    /* Space (32) */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* ! (33) */
    {0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00},
    /* " (34) */
    {0x6C, 0x6C, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* # (35) */
    {0x6C, 0x6C, 0xFE, 0x6C, 0xFE, 0x6C, 0x6C, 0x00},
    /* $ (36) */
    {0x18, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00},
    /* % (37) */
    {0x00, 0xC6, 0xCC, 0x18, 0x30, 0x66, 0xC6, 0x00},
    /* & (38) */
    {0x38, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0x76, 0x00},
    /* ' (39) */
    {0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* ( (40) */
    {0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00},
    /* ) (41) */
    {0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00},
    /* * (42) */
    {0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00},
    /* + (43) */
    {0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00},
    /* , (44) */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30},
    /* - (45) */
    {0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00},
    /* . (46) */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00},
    /* / (47) */
    {0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00},
    /* 0 (48) */
    {0x7C, 0xCE, 0xDE, 0xF6, 0xE6, 0xC6, 0x7C, 0x00},
    /* 1 (49) */
    {0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00},
    /* 2 (50) */
    {0x7C, 0xC6, 0x06, 0x1C, 0x70, 0xC6, 0xFE, 0x00},
    /* 3 (51) */
    {0x7C, 0xC6, 0x06, 0x3C, 0x06, 0xC6, 0x7C, 0x00},
    /* 4 (52) */
    {0x1C, 0x3C, 0x6C, 0xCC, 0xFE, 0x0C, 0x1E, 0x00},
    /* 5 (53) */
    {0xFE, 0xC0, 0xFC, 0x06, 0x06, 0xC6, 0x7C, 0x00},
    /* 6 (54) */
    {0x38, 0x60, 0xC0, 0xFC, 0xC6, 0xC6, 0x7C, 0x00},
    /* 7 (55) */
    {0xFE, 0xC6, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00},
    /* 8 (56) */
    {0x7C, 0xC6, 0xC6, 0x7C, 0xC6, 0xC6, 0x7C, 0x00},
    /* 9 (57) */
    {0x7C, 0xC6, 0xC6, 0x7E, 0x06, 0x0C, 0x78, 0x00},
    /* : (58) */
    {0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00},
    /* ; (59) */
    {0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30},
    /* < (60) */
    {0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x00},
    /* = (61) */
    {0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00},
    /* > (62) */
    {0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x00},
    /* ? (63) */
    {0x7C, 0xC6, 0x0C, 0x18, 0x18, 0x00, 0x18, 0x00},
    /* @ (64) */
    {0x7C, 0xC6, 0xDE, 0xDE, 0xDC, 0xC0, 0x7C, 0x00},
    /* A (65) */
    {0x38, 0x6C, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0x00},
    /* B (66) */
    {0xFC, 0xC6, 0xC6, 0xFC, 0xC6, 0xC6, 0xFC, 0x00},
    /* C (67) */
    {0x7C, 0xC6, 0xC0, 0xC0, 0xC0, 0xC6, 0x7C, 0x00},
    /* D (68) */
    {0xF8, 0xCC, 0xC6, 0xC6, 0xC6, 0xCC, 0xF8, 0x00},
    /* E (69) */
    {0xFE, 0xC0, 0xC0, 0xF8, 0xC0, 0xC0, 0xFE, 0x00},
    /* F (70) */
    {0xFE, 0xC0, 0xC0, 0xF8, 0xC0, 0xC0, 0xC0, 0x00},
    /* G (71) */
    {0x7C, 0xC6, 0xC0, 0xCE, 0xC6, 0xC6, 0x7E, 0x00},
    /* H (72) */
    {0xC6, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0x00},
    /* I (73) */
    {0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00},
    /* J (74) */
    {0x1E, 0x06, 0x06, 0x06, 0xC6, 0xC6, 0x7C, 0x00},
    /* K (75) */
    {0xC6, 0xCC, 0xD8, 0xF0, 0xD8, 0xCC, 0xC6, 0x00},
    /* L (76) */
    {0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xFE, 0x00},
    /* M (77) */
    {0xC6, 0xEE, 0xFE, 0xD6, 0xC6, 0xC6, 0xC6, 0x00},
    /* N (78) */
    {0xC6, 0xE6, 0xF6, 0xDE, 0xCE, 0xC6, 0xC6, 0x00},
    /* O (79) */
    {0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00},
    /* P (80) */
    {0xFC, 0xC6, 0xC6, 0xFC, 0xC0, 0xC0, 0xC0, 0x00},
    /* Q (81) */
    {0x7C, 0xC6, 0xC6, 0xC6, 0xD6, 0xDE, 0x7C, 0x06},
    /* R (82) */
    {0xFC, 0xC6, 0xC6, 0xFC, 0xD8, 0xCC, 0xC6, 0x00},
    /* S (83) */
    {0x7C, 0xC6, 0x60, 0x38, 0x0C, 0xC6, 0x7C, 0x00},
    /* T (84) */
    {0xFF, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00},
    /* U (85) */
    {0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00},
    /* V (86) */
    {0xC6, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x10, 0x00},
    /* W (87) */
    {0xC6, 0xC6, 0xC6, 0xD6, 0xFE, 0xEE, 0xC6, 0x00},
    /* X (88) */
    {0xC6, 0xC6, 0x6C, 0x38, 0x6C, 0xC6, 0xC6, 0x00},
    /* Y (89) */
    {0xC3, 0xC3, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00},
    /* Z (90) */
    {0xFE, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0xFE, 0x00},
    /* [ (91) */
    {0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00},
    /* \ (92) */
    {0xC0, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00},
    /* ] (93) */
    {0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00},
    /* ^ (94) */
    {0x10, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00},
    /* _ (95) */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF},
    /* ` (96) */
    {0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* a (97) */
    {0x00, 0x00, 0x7C, 0x06, 0x7E, 0xC6, 0x7E, 0x00},
    /* b (98) */
    {0xC0, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0xFC, 0x00},
    /* c (99) */
    {0x00, 0x00, 0x7C, 0xC6, 0xC0, 0xC6, 0x7C, 0x00},
    /* d (100) */
    {0x06, 0x06, 0x7E, 0xC6, 0xC6, 0xC6, 0x7E, 0x00},
    /* e (101) */
    {0x00, 0x00, 0x7C, 0xC6, 0xFE, 0xC0, 0x7C, 0x00},
    /* f (102) */
    {0x1C, 0x36, 0x30, 0x78, 0x30, 0x30, 0x30, 0x00},
    /* g (103) */
    {0x00, 0x00, 0x7E, 0xC6, 0xC6, 0x7E, 0x06, 0x7C},
    /* h (104) */
    {0xC0, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0xC6, 0x00},
    /* i (105) */
    {0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00},
    /* j (106) */
    {0x06, 0x00, 0x0E, 0x06, 0x06, 0xC6, 0xC6, 0x7C},
    /* k (107) */
    {0xC0, 0xC0, 0xC6, 0xCC, 0xF8, 0xCC, 0xC6, 0x00},
    /* l (108) */
    {0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00},
    /* m (109) */
    {0x00, 0x00, 0xEC, 0xFE, 0xD6, 0xC6, 0xC6, 0x00},
    /* n (110) */
    {0x00, 0x00, 0xFC, 0xC6, 0xC6, 0xC6, 0xC6, 0x00},
    /* o (111) */
    {0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7C, 0x00},
    /* p (112) */
    {0x00, 0x00, 0xFC, 0xC6, 0xC6, 0xFC, 0xC0, 0xC0},
    /* q (113) */
    {0x00, 0x00, 0x7E, 0xC6, 0xC6, 0x7E, 0x06, 0x06},
    /* r (114) */
    {0x00, 0x00, 0xDC, 0xE6, 0xC0, 0xC0, 0xC0, 0x00},
    /* s (115) */
    {0x00, 0x00, 0x7E, 0xC0, 0x7C, 0x06, 0xFC, 0x00},
    /* t (116) */
    {0x30, 0x30, 0x7C, 0x30, 0x30, 0x36, 0x1C, 0x00},
    /* u (117) */
    {0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0x7E, 0x00},
    /* v (118) */
    {0x00, 0x00, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x00},
    /* w (119) */
    {0x00, 0x00, 0xC6, 0xC6, 0xD6, 0xFE, 0x6C, 0x00},
    /* x (120) */
    {0x00, 0x00, 0xC6, 0x6C, 0x38, 0x6C, 0xC6, 0x00},
    /* y (121) */
    {0x00, 0x00, 0xC6, 0xC6, 0xC6, 0x7E, 0x06, 0x7C},
    /* z (122) */
    {0x00, 0x00, 0xFE, 0x0C, 0x38, 0x60, 0xFE, 0x00},
    /* { (123) */
    {0x0E, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0E, 0x00},
    /* | (124) */
    {0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00},
    /* } (125) */
    {0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00},
    /* ~ (126) */
    {0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* DEL (127) - filled block */
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};

/* Console state */
static struct {
    IDirect3D8 *d3d;
    IDirect3DDevice8 *device;
    int screen_width;
    int screen_height;
    int cols;
    int rows;
    int cursor_x;
    int cursor_y;
    unsigned int fg_color;
    unsigned int bg_color;
    int initialized;
    /* Off-screen buffer for content (we redraw each frame) */
    unsigned int *buffer;
    int buffer_size;
} console = {0};

#define CHAR_WIDTH  8
#define CHAR_HEIGHT 8

/* Internal: Draw a single character to our buffer */
static void draw_char_to_buffer(int cx, int cy, char c, unsigned int fg, unsigned int bg)
{
    int idx;
    int row, col;
    const unsigned char *glyph;
    int px, py;
    unsigned int *pixel;

    if (!console.buffer) return;

    px = cx * CHAR_WIDTH;
    py = cy * CHAR_HEIGHT;

    if (px < 0 || py < 0) return;
    if (px + CHAR_WIDTH > console.screen_width) return;
    if (py + CHAR_HEIGHT > console.screen_height) return;

    /* Get glyph for character */
    idx = (int)(unsigned char)c - 32;
    if (idx < 0 || idx >= 96) idx = 0;  /* Default to space */
    glyph = font_8x8[idx];

    /* Draw the character to buffer */
    for (row = 0; row < CHAR_HEIGHT; row++) {
        pixel = console.buffer + (py + row) * console.screen_width + px;
        for (col = 0; col < CHAR_WIDTH; col++) {
            if (glyph[row] & (0x80 >> col)) {
                *pixel = fg;
            } else {
                *pixel = bg;
            }
            pixel++;
        }
    }
}

int xbox_console_init(int width, int height)
{
    D3DPRESENT_PARAMETERS d3dpp;
    HRESULT hr;

    if (console.initialized) return 1;

    console.screen_width = width;
    console.screen_height = height;
    console.cols = width / CHAR_WIDTH;
    console.rows = height / CHAR_HEIGHT;
    console.cursor_x = 0;
    console.cursor_y = 0;
    console.fg_color = CONSOLE_COLOR_WHITE;
    console.bg_color = CONSOLE_COLOR_BLACK;

    /* Allocate off-screen buffer */
    console.buffer_size = width * height * sizeof(unsigned int);
    console.buffer = (unsigned int *)malloc(console.buffer_size);
    if (!console.buffer) {
        OutputDebugStringA("Failed to allocate console buffer\n");
        return 0;
    }

    /* Create Direct3D object */
    console.d3d = Direct3DCreate8(D3D_SDK_VERSION);
    if (!console.d3d) {
        OutputDebugStringA("Failed to create Direct3D8\n");
        free(console.buffer);
        console.buffer = NULL;
        return 0;
    }

    /* Setup presentation parameters - match Microsoft SDK patterns */
    ZeroMemory(&d3dpp, sizeof(d3dpp));
    d3dpp.BackBufferWidth = width;
    d3dpp.BackBufferHeight = height;
    d3dpp.BackBufferFormat = D3DFMT_X8R8G8B8;  /* Standard swizzled format */
    d3dpp.BackBufferCount = 1;
    d3dpp.EnableAutoDepthStencil = FALSE;
    d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    d3dpp.FullScreen_RefreshRateInHz = 60;
    d3dpp.FullScreen_PresentationInterval = D3DPRESENT_INTERVAL_ONE;

    /* Create device */
    hr = console.d3d->CreateDevice(0, D3DDEVTYPE_HAL, NULL,
                                    D3DCREATE_HARDWARE_VERTEXPROCESSING,
                                    &d3dpp, &console.device);
    if (FAILED(hr)) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "Failed to create D3D device: 0x%08X\n", hr);
        buf[sizeof(buf) - 1] = '\0';
        OutputDebugStringA(buf);
        console.d3d->Release();
        console.d3d = NULL;
        free(console.buffer);
        console.buffer = NULL;
        return 0;
    }

    console.initialized = 1;

    /* Clear buffer to background color */
    xbox_console_clear(console.bg_color);

    return 1;
}

void xbox_console_shutdown(void)
{
    if (!console.initialized) return;

    if (console.device) {
        console.device->Release();
        console.device = NULL;
    }
    if (console.d3d) {
        console.d3d->Release();
        console.d3d = NULL;
    }
    if (console.buffer) {
        free(console.buffer);
        console.buffer = NULL;
    }

    console.initialized = 0;
}

void xbox_console_clear(unsigned int color)
{
    int i;
    int total_pixels;

    if (!console.initialized || !console.buffer) return;

    total_pixels = console.screen_width * console.screen_height;
    for (i = 0; i < total_pixels; i++) {
        console.buffer[i] = color;
    }

    console.cursor_x = 0;
    console.cursor_y = 0;
    console.bg_color = color;
}

void xbox_console_set_colors(unsigned int foreground, unsigned int background)
{
    console.fg_color = foreground;
    console.bg_color = background;
}

void xbox_console_set_cursor(int x, int y)
{
    if (x >= 0 && x < console.cols) console.cursor_x = x;
    if (y >= 0 && y < console.rows) console.cursor_y = y;
}

void xbox_console_get_cursor(int *x, int *y)
{
    if (x) *x = console.cursor_x;
    if (y) *y = console.cursor_y;
}

void xbox_console_scroll(void)
{
    int row;
    unsigned int *src, *dst;
    int line_bytes;

    if (!console.initialized || !console.buffer) return;

    /* Move all lines up by one character row */
    line_bytes = console.screen_width * CHAR_HEIGHT * sizeof(unsigned int);
    for (row = 0; row < console.rows - 1; row++) {
        dst = console.buffer + row * CHAR_HEIGHT * console.screen_width;
        src = console.buffer + (row + 1) * CHAR_HEIGHT * console.screen_width;
        memcpy(dst, src, line_bytes);
    }

    /* Clear the last line */
    dst = console.buffer + (console.rows - 1) * CHAR_HEIGHT * console.screen_width;
    for (row = 0; row < CHAR_HEIGHT * console.screen_width; row++) {
        dst[row] = console.bg_color;
    }
}

void xbox_console_putchar(char c)
{
    if (!console.initialized) return;

    /* Handle special characters */
    switch (c) {
    case '\n':
        console.cursor_x = 0;
        console.cursor_y++;
        break;
    case '\r':
        console.cursor_x = 0;
        break;
    case '\t':
        console.cursor_x = (console.cursor_x + 4) & ~3;
        break;
    case '\b':
        if (console.cursor_x > 0) console.cursor_x--;
        break;
    default:
        if (c >= 32 && c < 127) {
            draw_char_to_buffer(console.cursor_x, console.cursor_y,
                               c, console.fg_color, console.bg_color);
            console.cursor_x++;
        }
        break;
    }

    /* Handle line wrap */
    if (console.cursor_x >= console.cols) {
        console.cursor_x = 0;
        console.cursor_y++;
    }

    /* Handle scroll */
    if (console.cursor_y >= console.rows) {
        xbox_console_scroll();
        console.cursor_y = console.rows - 1;
    }
}

void xbox_console_print(const char *str)
{
    if (!str) return;
    while (*str) {
        xbox_console_putchar(*str++);
    }
}

void xbox_console_println(const char *str)
{
    xbox_console_print(str);
    xbox_console_putchar('\n');
}

void xbox_console_printf(const char *format, ...)
{
    char buffer[512];
    va_list args;

    va_start(args, format);
    _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    buffer[sizeof(buffer) - 1] = '\0';
    va_end(args);

    xbox_console_print(buffer);
}

void xbox_console_draw_line(char c, int count)
{
    int i;
    for (i = 0; i < count && console.cursor_x < console.cols; i++) {
        xbox_console_putchar(c);
    }
}

void xbox_console_draw_box(int x1, int y1, int x2, int y2)
{
    int i;

    /* Top border */
    xbox_console_set_cursor(x1, y1);
    xbox_console_putchar('+');
    for (i = x1 + 1; i < x2; i++) {
        xbox_console_putchar('-');
    }
    xbox_console_putchar('+');

    /* Side borders */
    for (i = y1 + 1; i < y2; i++) {
        xbox_console_set_cursor(x1, i);
        xbox_console_putchar('|');
        xbox_console_set_cursor(x2, i);
        xbox_console_putchar('|');
    }

    /* Bottom border */
    xbox_console_set_cursor(x1, y2);
    xbox_console_putchar('+');
    for (i = x1 + 1; i < x2; i++) {
        xbox_console_putchar('-');
    }
    xbox_console_putchar('+');
}

void xbox_console_present(void)
{
    IDirect3DSurface8 *backbuffer = NULL;
    D3DLOCKED_RECT locked;
    HRESULT hr;
    int y;
    unsigned int *src;
    unsigned char *dst;

    if (!console.initialized || !console.device || !console.buffer) return;

    /* Get backbuffer fresh each frame (Microsoft pattern) */
    hr = console.device->GetBackBuffer(0, D3DBACKBUFFER_TYPE_MONO, &backbuffer);
    if (FAILED(hr) || !backbuffer) {
        OutputDebugStringA("GetBackBuffer failed\n");
        return;
    }

    /* Lock with D3DLOCK_TILED for linear access to swizzled surface */
    hr = backbuffer->LockRect(&locked, NULL, D3DLOCK_TILED);
    if (FAILED(hr)) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "LockRect failed: 0x%08X\n", hr);
        buf[sizeof(buf) - 1] = '\0';
        OutputDebugStringA(buf);
        backbuffer->Release();
        return;
    }

    /* Copy our buffer to backbuffer, respecting pitch */
    src = console.buffer;
    dst = (unsigned char *)locked.pBits;
    for (y = 0; y < console.screen_height; y++) {
        memcpy(dst, src, console.screen_width * sizeof(unsigned int));
        src += console.screen_width;
        dst += locked.Pitch;
    }

    /* Unlock before present */
    backbuffer->UnlockRect();

    /* Release backbuffer reference */
    backbuffer->Release();

    /* Present */
    console.device->Present(NULL, NULL, NULL, NULL);
}

void xbox_console_get_size(int *cols, int *rows)
{
    if (cols) *cols = console.cols;
    if (rows) *rows = console.rows;
}
