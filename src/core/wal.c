/*
The fundamental rule of WAL is:
Log the changes BEFORE writing the actual data to the disk.

https://en.wikipedia.org/wiki/Non-volatile_memory
Non-volatile memory (NVM) or non-volatile storage is a type of computer memory that can retain stored information even after power is removed. 
In contrast, volatile memory needs constant power in order to retain data.
*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

/*
magic, version, pagesize, 
*/
static const int WAL_MAGIC_NUMBER = 0x4B43594B;
static const int WAL_VERSION = 1;
static const int WAL_PAGE_SIZE = 4096;
static const int WAL_MAX_RECORD_SIZE = WAL_PAGE_SIZE * 4; // warning, standard ? 
static const int WAL_DEFAULT_FILE_SIZE = 16 * 1024 * 1024; // 16MB
/*
What is a Checkpoint?

A checkpoint is a point in time where:

All modified data in memory is flushed to disk
The WAL records up to that point are no longer needed for recovery
Old WAL records can be discarded or overwritten
*/
static const int WAL_CHECKPOINT_INTERVAL = 1000; 

enum wal_record_type {
    WAL_RECORD_ALLOC = 1,        // Allocation operation
    WAL_RECORD_FREE,             // Free operation
    WAL_RECORD_SPLIT,            // Block split
    WAL_RECORD_COALESCE,         // Block merge
    WAL_RECORD_REGION_CREATE,    // New region creation
    WAL_RECORD_REGION_DESTROY,   // Region destruction
    WAL_RECORD_CHECKPOINT,       // Checkpoint marker
    WAL_RECORD_COMMIT,           // Transaction commit
    WAL_RECORD_ABORT,            // Transaction abort
    WAL_RECORD_METADATA_UPDATE   // Metadata modification
};

struct wal_header {
    uint32_t magic;  
    uint32_t version; 
    uint64_t last_lsn;           // Last Log Sequence Number
    uint64_t last_checkpoint_lsn;// LSN of last checkpoint
    uint64_t last_checkpoint_time;// Timestamp of last checkpoint
    uint32_t page_size;          // (usually 4096)
    uint32_t record_count; 
    uint32_t checksum; 
    uint32_t flags;              // WAL flags (e.g., dirty, clean)
    uint8_t  reserved[32];       // Reserved for future use
} __attribute__((packed));

struct wal_record_header {
    uint64_t lsn;                // Log Sequence Number (unique, increasing)
    uint64_t prev_lsn; 
    uint64_t transaction_id; 
    uint32_t record_type;        // Type of record (from enum)
    uint32_t record_size;        // Size of this record (including header)
    uint32_t data_size;   
    uint32_t crc32;   
    uint32_t flags;              // Record flags (e.g., compressed, encrypted)
    uint64_t timestamp;   
    uint8_t  padding[16]; 
} __attribute__((packed));

// WAL PAYLOAD TYPES
struct wal_alloc_payload {
    // warning name
    void *user_ptr;              // User-facing pointer (what user gets) 
    void *block_ptr;             // Block header pointer (internal)
    /*
    region -> block1, block2...

Heap Region (large chunk from OS, typically 2MB+)
├── Block 1 (small allocation unit, e.g., 32 bytes)
├── Block 2
├── Block 3
├── ...
└── Block N

Region 2 (another large chunk)
├── Block 1
├── Block 2
└── ...

Region 3
└── ...

--- REGION (2MB from OS) ---
┌─────────────────────────────────────────────────┐
│ Region metadata (struct heap_region)            │
│  - base: 0x100000                               │
│  - size: 2MB                                    │
│  - canary: 0xDEADBEEF                           │
├─────────────────────────────────────────────────┤
│ BLOCK 1 (32 bytes)                              │
│  - block_header (metadata)                      │
│  - user data                                    │
├─────────────────────────────────────────────────┤
│ BLOCK 2 (64 bytes)                              │
│  - block_header                                 │
│  - user data                                    │
├─────────────────────────────────────────────────┤
│ BLOCK 3 (32 bytes)                              │
│  - block_header                                 │
│  - user data                                    │
├─────────────────────────────────────────────────┤
│ ... more blocks ...                             │
└─────────────────────────────────────────────────┘
    */
    uint64_t region_id;          // Region identifier
    /*
    (!) Why Store block_size in WAL When We Have block_ptr? (!)

    1. The block header might be corrupted or unavailable during recovery
// During normal operation, you can do this:
struct block_header *block = (struct block_header *)block_ptr;
uint32_t size = block->size;  // Get size from header

// BUT during crash recovery:
// - The block header might be corrupted
// - The memory might not be accessible
// - The block might have been partially written
// - The canary might be invalid

- In WAL recovery, you need the size without relying on the potentially corrupted block header. <--- IT's important !

2. WAL records should be self-contained

A good WAL record should contain all information needed for recovery !

3. The size might change between logging and recovery

// Time of allocation:
block->size = 128;  // Original size
wal_write_alloc(wal, user_ptr, block_ptr, 128);

// Later... block gets split:
block->size = 64;   // Changed!
new_block->size = 64;

// During recovery, if we read block->size, we get 64, not 128
// But the WAL record has the original size: 128!

4. Performance optimization (preventing cache misses and etc);

5. Validation and consistency checking
// You can verify that the stored size matches the actual header
bool validate_record(wal_record_t *record) {
    struct block_header *block = (struct block_header *)record->block_ptr;
    
    if (block->size != record->block_size) {
        // Corruption detected!
        // The block was modified after logging
        return false;
    }
    
    return true;
}
    */
    uint32_t block_size;         // Size of allocated block
    uint32_t class_index;        // Size class index
    uint32_t thread_id;          // Thread that performed allocation
    uint32_t alignment;          // Alignment used
};

struct wal_free_payload {
    void *user_ptr;
    void *block_ptr;
    uint64_t region_id;
    uint32_t block_size;
    uint32_t thread_id;
    uint32_t free_reason;
};

// large file -> small files (roughly speaking)
struct wal_split_payload {
    void *original_block;
    void *new_block;
    uint32_t original_size;
    uint32_t new_size;
    uint32_t remaining_size;
};

// small files -> large files (roughly speaking)
struct wal_coalesce_payload {
    void *block1;
    void *block2;
    uint32_t block1_size;
    uint32_t block2_size;
    uint32_t coalesced_size;
};

struct wal_region_payload {
    void *region_base;
    uint32_t region_id;
    uint32_t region_size;
    uint32_t region_flags;
    uint32_t canary;
};

struct wal_checkpoint_payload {
    uint64_t checkpoint_lsn;
    uint32_t total_regions; 
    uint32_t total_allocations; 
    uint32_t total_frees;  
    uint64_t total_memory;       
    uint64_t free_memory;     
};

struct wal_record {
    struct wal_record_header header;

    struct wal_paylod {
        struct wal_alloc_payload alloc;
        struct wal_free_payload free;
        struct wal_split_payload split;
        struct wal_coalesce_payload coalesce;
        struct wal_region_payload region;
        struct wal_checkpoint_payload checkpoint;
        uint8_t raw_data[WAL_MAX_RECORD_SIZE];
    };
};

// WAL FILE STRUCTURE
struct wal_file {
    struct wal_header header;
    struct wal_record records[];
};

// WAL BUFFER
struct wal_buffer {
    uint8_t *buffer;
    size_t buffer_size;
    size_t current_offset;
    size_t flush_offset;
    uint64_t current_lsn;
    pthread_mutex_t buffer_lock;
};

struct wal_context {
    char *wal_file_path;  
    int wal_file_fd;
    bool is_open;

    struct wal_buffer buffer;

    // State tracking
    uint64_t last_lsn; 
    uint64_t last_flushed_lsn;  
    uint64_t last_checkpoint_lsn; 
    uint64_t transaction_id; 

    // Statistics
    uint64_t total_records_written;
    uint64_t total_records_flushed;
    uint64_t total_bytes_written;
    uint64_t total_bytes_flushed;
    uint64_t total_flushes;
    uint64_t total_checkpoints;

    // Synchronization
    pthread_mutex_t wal_lock;    // Main WAL lock
    pthread_cond_t flush_cond;   // Condition for flush notification
    bool flush_requested;        // Flush requested flag
    bool checkpoint_requested;   // Checkpoint requested flag

    // Callbacks
    void (*on_flush)(void *ctx);           // Called after flush
    void (*on_checkpoint)(void *ctx);      // Called after checkpoint
    void (*on_recovery)(void *ctx);        // Called during recovery
    void *callback_ctx;                     // Context for callbacks

    // Recovery state
    bool in_recovery;            // Is recovery in progress
    uint32_t recovery_errors;    // Number of errors during recovery
};

struct wal_operation {
    struct wal_context *context; 
    uint64_t lsn;     
    uint64_t transaction_id;    
    bool is_active;    
    bool needs_commit; 
};