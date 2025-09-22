#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <notification/notification.h>
#include <storage/storage.h>
#include <stdint.h>
#include <string.h>

#define TAG "BLE_Sniffer"

// UART Configuration (placeholder for future implementation)
#define BUFFER_SIZE 1024

// BLE Packet Structure (from nRF Sniffer)
typedef struct {
    uint32_t timestamp;
    uint8_t channel;
    uint8_t rssi;
    uint16_t packet_length;
    uint8_t packet_data[255];
} ble_packet_t;

// PCAP Structures
typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

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
    
    // UART
    uint8_t uart_buffer[BUFFER_SIZE];
    size_t uart_buffer_pos;
    bool uart_data_ready;
    
    // Connection detection
    uint32_t last_data_time;
    uint32_t connection_check_time;
    
    // Packet simulation for testing
    uint32_t last_packet_time;
    
    // Storage
    Storage* storage;
    File* current_file;
    char current_filename[64];
    
    // UI
    char status_text[128];
    char info_text[128];
} BLE_SnifferApp;

// PCAP Constants
#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define BLE_DLT 251

// Forward declarations
static void ble_sniffer_render_callback(Canvas* canvas, void* context);
static void ble_sniffer_input_callback(InputEvent* input_event, void* context);
static void ble_sniffer_create_pcap_file(BLE_SnifferApp* app);
static void ble_sniffer_write_packet(BLE_SnifferApp* app, ble_packet_t* packet);

// Create new PCAP file
static void ble_sniffer_create_pcap_file(BLE_SnifferApp* app) {
    if(app->current_file) {
        storage_file_close(app->current_file);
        storage_file_free(app->current_file);
    }
    
    // Generate filename
    snprintf(app->current_filename, sizeof(app->current_filename), 
             "/ext/ble_capture_%lu.pcap", app->file_count++);
    
    // Create file
    app->current_file = storage_file_alloc(app->storage);
    if(storage_file_open(app->current_file, app->current_filename, 
                        FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        
        // Write PCAP header
        pcap_header_t pcap_hdr = {
            .magic_number = PCAP_MAGIC_NUMBER,
            .version_major = PCAP_VERSION_MAJOR,
            .version_minor = PCAP_VERSION_MINOR,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = 65535,
            .network = BLE_DLT
        };
        
        storage_file_write(app->current_file, &pcap_hdr, sizeof(pcap_hdr));
        storage_file_sync(app->current_file);
        
        FURI_LOG_I(TAG, "Created PCAP file: %s", app->current_filename);
    } else {
        FURI_LOG_E(TAG, "Failed to create PCAP file: %s", app->current_filename);
    }
}

// Write packet to PCAP file
static void ble_sniffer_write_packet(BLE_SnifferApp* app, ble_packet_t* packet) {
    if(!app->current_file || !storage_file_is_open(app->current_file)) {
        return;
    }
    
    // Create packet header
    pcap_packet_header_t pkt_hdr = {
        .ts_sec = packet->timestamp / 1000,
        .ts_usec = (packet->timestamp % 1000) * 1000,
        .incl_len = packet->packet_length,
        .orig_len = packet->packet_length
    };
    
    // Write packet header and data
    storage_file_write(app->current_file, &pkt_hdr, sizeof(pkt_hdr));
    storage_file_write(app->current_file, packet->packet_data, packet->packet_length);
    storage_file_sync(app->current_file);
    
    app->packet_count++;
}

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
    if(app->state == BLE_SnifferStateCapturing) {
        canvas_draw_str(canvas, 2, 111, "Right: New File");
    } else {
        canvas_draw_str(canvas, 2, 111, "Right: Test Conn");
    }
}

// Input callback
static void ble_sniffer_input_callback(InputEvent* input_event, void* context) {
    BLE_SnifferApp* app = context;
    
    if(input_event->type == InputTypeShort) {
        switch(input_event->key) {
            case InputKeyOk:
                if(app->state == BLE_SnifferStateIdle) {
                    app->state = BLE_SnifferStateCapturing;
                    app->packet_count = 0; // Reset packet count
                    ble_sniffer_create_pcap_file(app); // Create new PCAP file
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
                    // Create new PCAP file while capturing
                    ble_sniffer_create_pcap_file(app);
                    // notification_message(app->notification, &sequence_blink_green);
                } else {
                    // Manual connection test when not capturing
                    app->is_connected = !app->is_connected;
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
    
    // Initialize UART (placeholder for future implementation)
    app->uart_buffer_pos = 0;
    app->uart_data_ready = false;
    app->last_data_time = 0;
    app->connection_check_time = 0;
    app->last_packet_time = 0;
    // TODO: Add UART initialization when SDK supports it
    
    // Initial state
    app->state = BLE_SnifferStateIdle;
    app->is_connected = false; // Start as disconnected
    
    FURI_LOG_I(TAG, "BLE Sniffer started");
    
    // Main loop
    InputEvent event;
    while(1) {
        uint32_t current_time = furi_get_tick();
        
        // Process input events
        if(furi_message_queue_get(app->event_queue, &event, 100) == FuriStatusOk) {
            ble_sniffer_input_callback(&event, app);
        }
        
        // Simulate packet generation for testing PCAP functionality
        if(app->state == BLE_SnifferStateCapturing && 
           current_time - app->last_packet_time > 5000) { // Every 5 seconds
            app->last_packet_time = current_time;
            
            // Create a dummy BLE packet for testing
            if(app->current_file && storage_file_is_open(app->current_file)) {
                ble_packet_t dummy_packet = {
                    .timestamp = current_time,
                    .channel = 37, // BLE advertising channel
                    .rssi = 80,
                    .packet_length = 20,
                    .packet_data = {
                        0x02, 0x01, 0x06, 0x1A, 0xFF, 0x4C, 0x00, 0x02,
                        0x15, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
                        0xF0, 0x12, 0x34, 0x56
                    }
                };
                ble_sniffer_write_packet(app, &dummy_packet);
            }
        }
        
        // Process UART data (placeholder for future implementation)
        if(app->uart_data_ready && app->state == BLE_SnifferStateCapturing) {
            // TODO: Parse actual BLE packets from nRF52840
            app->uart_buffer_pos = 0;
            app->uart_data_ready = false;
            app->last_data_time = furi_get_tick();
        }
        
        // Connection detection (check every 2 seconds)
        if(current_time - app->connection_check_time > 2000) {
            app->connection_check_time = current_time;
            
            // For now, simulate connection detection
            // TODO: Replace with actual UART data detection
            // This is a placeholder - in real implementation, check if UART has data
            static bool simulated_connection = false;
            static uint32_t last_simulated_check = 0;
            
            // Simulate connection detection every 10 seconds for testing
            if(current_time - last_simulated_check > 10000) {
                simulated_connection = !simulated_connection;
                last_simulated_check = current_time;
            }
            
            app->is_connected = simulated_connection;
        }
        
        // Check if view port is still enabled
        if(!view_port_is_enabled(app->view_port)) {
            break;
        }
    }
    
    // Cleanup
    // TODO: Cleanup UART when implemented
    
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