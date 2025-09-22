#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <notification/notification.h>
#include <storage/storage.h>
#include <stdint.h>
#include <string.h>

#define TAG "BLE_Sniffer"

// App State
typedef enum {
    BLE_SnifferStateIdle,
    BLE_SnifferStateCapturing,
    BLE_SnifferStatePaused
} BLE_SnifferState;

typedef struct {
    FuriMessageQueue* event_queue;
    ViewPort* view_port;
    Gui* gui;
    NotificationApp* notification;
    
    BLE_SnifferState state;
    bool is_connected;
    uint32_t packet_count;
    uint32_t file_count;
    
    // Storage
    Storage* storage;
    File* current_file;
    char current_filename[64];
    
    // UI
    char status_text[128];
    char info_text[128];
} BLE_SnifferApp;

// Render callback
static void ble_sniffer_render_callback(Canvas* canvas, void* context) {
    BLE_SnifferApp* app = context;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "BLE Sniffer");
    
    canvas_set_font(canvas, FontSecondary);
    
    // Status
    switch(app->state) {
        case BLE_SnifferStateIdle:
            canvas_draw_str(canvas, 2, 25, "Status: Idle");
            break;
        case BLE_SnifferStateCapturing:
            canvas_draw_str(canvas, 2, 25, "Status: Capturing");
            break;
        case BLE_SnifferStatePaused:
            canvas_draw_str(canvas, 2, 25, "Status: Paused");
            break;
    }
    
    // Connection status
    if(app->is_connected) {
        canvas_draw_str(canvas, 2, 37, "nRF52840: Connected");
    } else {
        canvas_draw_str(canvas, 2, 37, "nRF52840: Disconnected");
    }
    
    // Packet count
    snprintf(app->info_text, sizeof(app->info_text), 
             "Packets: %lu", app->packet_count);
    canvas_draw_str(canvas, 2, 49, app->info_text);
    
    // Current file
    if(app->current_filename[0]) {
        canvas_draw_str(canvas, 2, 61, "File: ble_capture_*.pcap");
    }
    
    // Controls
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 75, "OK: Start/Stop");
    canvas_draw_str(canvas, 2, 87, "Back: Exit");
    canvas_draw_str(canvas, 2, 99, "Left: Pause");
    canvas_draw_str(canvas, 2, 111, "Right: New File");
}

// Input callback
static void ble_sniffer_input_callback(InputEvent* input_event, void* context) {
    BLE_SnifferApp* app = context;
    
    if(input_event->type == InputTypeShort) {
        switch(input_event->key) {
            case InputKeyOk:
                if(app->state == BLE_SnifferStateIdle) {
                    app->state = BLE_SnifferStateCapturing;
                    app->packet_count++;
                    // notification_message(app->notification, &sequence_blink_blue);
                } else if(app->state == BLE_SnifferStateCapturing) {
                    app->state = BLE_SnifferStateIdle;
                    // notification_message(app->notification, &sequence_blink_red);
                } else if(app->state == BLE_SnifferStatePaused) {
                    app->state = BLE_SnifferStateCapturing;
                    // notification_message(app->notification, &sequence_blink_blue);
                }
                break;
                
            case InputKeyBack:
                if(app->current_file) {
                    storage_file_close(app->current_file);
                    storage_file_free(app->current_file);
                    app->current_file = NULL;
                }
                view_port_enabled_set(app->view_port, false);
                break;
                
            case InputKeyLeft:
                if(app->state == BLE_SnifferStateCapturing) {
                    app->state = BLE_SnifferStatePaused;
                    // notification_message(app->notification, &sequence_blink_yellow);
                }
                break;
                
            case InputKeyRight:
                if(app->state == BLE_SnifferStateCapturing) {
                    app->packet_count++;
                    app->file_count++;
                    // notification_message(app->notification, &sequence_blink_green);
                }
                break;
                
            default:
                // Handle other keys if needed
                break;
        }
    }
}

// Main application entry point
int32_t ble_sniffer_app(void* p) {
    UNUSED(p);
    
    BLE_SnifferApp* app = malloc(sizeof(BLE_SnifferApp));
    memset(app, 0, sizeof(BLE_SnifferApp));
    
    // Initialize
    app->event_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->view_port = view_port_alloc();
    app->gui = furi_record_open(RECORD_GUI);
    app->notification = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);
    
    // Set up GUI
    view_port_draw_callback_set(app->view_port, ble_sniffer_render_callback, app);
    view_port_input_callback_set(app->view_port, ble_sniffer_input_callback, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    
    // Initial state
    app->state = BLE_SnifferStateIdle;
    app->is_connected = true; // Assume connected for now
    
    FURI_LOG_I(TAG, "BLE Sniffer started");
    
    // Main loop
    InputEvent event;
    while(1) {
        // Process input events
        if(furi_message_queue_get(app->event_queue, &event, 100) == FuriStatusOk) {
            ble_sniffer_input_callback(&event, app);
        }
        
        // Check if view port is still enabled
        if(!view_port_is_enabled(app->view_port)) {
            break;
        }
    }
    
    // Cleanup
    if(app->current_file) {
        storage_file_close(app->current_file);
        storage_file_free(app->current_file);
    }
    
    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);
    furi_message_queue_free(app->event_queue);
    
    free(app);
    
    FURI_LOG_I(TAG, "BLE Sniffer stopped");
    
    return 0;
}