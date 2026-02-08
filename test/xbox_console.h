/*
 * Xbox Console Text Renderer
 * Direct framebuffer text rendering for Xbox
 *
 * Features:
 * - 8x8 bitmap font
 * - Color support (ARGB)
 * - Automatic scrolling
 * - No external dependencies
 */

#ifndef XBOX_CONSOLE_H
#define XBOX_CONSOLE_H

#include <xtl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Color definitions (ARGB format) */
#define CONSOLE_COLOR_BLACK     0xFF000000
#define CONSOLE_COLOR_WHITE     0xFFFFFFFF
#define CONSOLE_COLOR_RED       0xFFFF0000
#define CONSOLE_COLOR_GREEN     0xFF00FF00
#define CONSOLE_COLOR_BLUE      0xFF0000FF
#define CONSOLE_COLOR_YELLOW    0xFFFFFF00
#define CONSOLE_COLOR_CYAN      0xFF00FFFF
#define CONSOLE_COLOR_MAGENTA   0xFFFF00FF
#define CONSOLE_COLOR_ORANGE    0xFFFF8000
#define CONSOLE_COLOR_GRAY      0xFF808080
#define CONSOLE_COLOR_DARKGRAY  0xFF404040
#define CONSOLE_COLOR_LIGHTGRAY 0xFFC0C0C0

/* Initialize console with specified resolution */
/* width/height: 640x480 or 720x480 typically */
int xbox_console_init(int width, int height);

/* Clean up console resources */
void xbox_console_shutdown(void);

/* Clear screen with specified color */
void xbox_console_clear(unsigned int color);

/* Set text colors */
void xbox_console_set_colors(unsigned int foreground, unsigned int background);

/* Set cursor position (in character cells) */
void xbox_console_set_cursor(int x, int y);

/* Get current cursor position */
void xbox_console_get_cursor(int *x, int *y);

/* Print a single character */
void xbox_console_putchar(char c);

/* Print a string */
void xbox_console_print(const char *str);

/* Print a string with newline */
void xbox_console_println(const char *str);

/* Printf-style formatted output */
void xbox_console_printf(const char *format, ...);

/* Draw a horizontal line of characters */
void xbox_console_draw_line(char c, int count);

/* Draw a box around area (x1,y1) to (x2,y2) */
void xbox_console_draw_box(int x1, int y1, int x2, int y2);

/* Present/swap buffers (call after drawing to make visible) */
void xbox_console_present(void);

/* Scroll the console up by one line */
void xbox_console_scroll(void);

/* Get console dimensions in characters */
void xbox_console_get_size(int *cols, int *rows);

#ifdef __cplusplus
}
#endif

#endif /* XBOX_CONSOLE_H */
