#pragma once
#include "Default.h"
#include "MemoryPool.h"
#include "SinglePortModule.h"
#include "concurrency/NotifiedWorkerThread.h"

#define REPLAY_CACHE_MAX 10  // Max cache size, defined as percentage of available heap
#define REPLAY_CACHE_PRUNE 2 // Free this percentage of available heap when pruning
#define REPLAY_CACHE_MIN 16  // Min cache size, defined in packets
#define REPLAY_QUEUE_MAX 32  // Max number of packets to queue for replay (must be power of 2)
#define REPLAY_QUEUE_MASK (REPLAY_QUEUE_MAX - 1)
#define REPLAY_ENTRY_POOL_SIZE 512 // Sets the size of the packet tracking pool (must be power of 2)
#define REPLAY_ENTRY_POOL_MASK (REPLAY_ENTRY_POOL_SIZE - 1)
#define REPLAY_HT_BUCKETS 64                                    // How many buckets the hash table has
#define REPLAY_PRIORITY meshtastic_MeshPacket_Priority_RELIABLE // Priority for replay *protocol* packets
#define REPLAY_INTERVAL_MS 1000                                 // How often to wake up for periodic tasks
#define REPLAY_STATS_PRINT_SECS 10                              // How often to print stats
#define REPLAY_FLUSH_PACKETS 16                                 // Send an advertisement after this many rebroadcast packets
#define REPLAY_FLUSH_SECS 20                                    // Send an advertisement after this many seconds
#define REPLAY_SEQUENCE_MASK 0x1F                               // Mask for wrapping the advert sequence number
#define REPLAY_ADVERT_PACKETS_MASK 0x1F                         // Mask for wrapping the advert packet index
#define REPLAY_PACKET_SPACING 10          // Spacing between each replayed packet, in multiples of getTXDelayMsec()
#define REPLAY_PACKET_REQUEST_SPACING 100 // Spacing between requests for each missing packet, in multiples of getTXDelayMsec()
#define REPLAY_PACKET_REQUEST_HOLDOFF 40  // Initial holdoff before requesting a missing packet, in multiples of getTXDelayMsec()
#define REPLAY_MISSING_MAX 64             // Max number of missing packets to pursue replay for (must be power of 2)
#define REPLAY_MISSING_MASK (REPLAY_MISSING_MAX - 1)
#define REPLAY_MISSING_GIVEUP_SECS 300 // Give up trying to obtain missing packets after this many seconds
#define REPLAY_SERVER_TIMEOUT_SECS 300 // Forget servers we haven't heard from in this many seconds
#define REPLAY_SERVER_MAX 32           // Max number of replay servers to track (must be power of 2)
#define REPLAY_SERVER_MASK (REPLAY_SERVER_MAX - 1)
#define REPLAY_HOUSEKEEPING_MS 20000 // How often to notify for housekeeping tasks

#define REPLAY_DEFAULT_STATS_BROADCAST_SECS 300 // Default interval for stats broadcast
#define REPLAY_DEFAULT_FLUSH_PACKETS 16         // Send an advertisement after this many rebroadcast packets
#define REPLAY_DEFAULT_FLUSH_SECS 20            // Send an advertisement after this many seconds

#define REPLAY_NOTIFY_INIT 1     // Sent when the module is initialized
#define REPLAY_NOTIFY_INTERVAL 2 // Sent periodically, as needed for housekeeping
#define REPLAY_NOTIFY_FLUSH 3    // Sent when it's time to flush the current advert
#define REPLAY_NOTIFY_MISSING 4  // Sent when we discover a missing packet

#define REPLAY_TYPE_ADVERT_MAIN 0        // Default advertisement containing list of available packets
#define REPLAY_TYPE_ADVERT_PURGED 1      // List of packets that have been purged from the cache
#define REPLAY_TYPE_ADVERT_STATS 2       // Advertisement containing stats about this node
#define REPLAY_TYPE_ADVERT_RESERVED_3 3  // Reserved for future use
#define REPLAY_TYPE_REQUEST_PACKETS 0    // Request for packets to be replayed
#define REPLAY_TYPE_REQUEST_STATS 1      // Request current stats
#define REPLAY_TYPE_REQUEST_RESERVED_2 2 // Reserved for future use
#define REPLAY_TYPE_REQUEST_RESERVED_3 3 // Reserved for future use

#define REPLAY_HASH(a, b) ((((a ^ b) >> 16) ^ (a ^ b)) & 0xFFFF)
#define REPLAY_BUCKET(h) (((h >> 12) ^ (h >> 6) ^ h) & 0x3F)
#define REPLAY_CFG(a, b) (b ? b : a)
#define REPLAY_SPACING(a) (a * router->getTxDelayMsec())

typedef uint16_t ReplayHash;
typedef uint8_t ReplayPriority;

typedef union ReplayHeader {
    uint16_t bitfield = 0;
    struct {
        // Common fields
        uint16_t type : 2;     // Packet type
        uint16_t priority : 2; // Lowest priority (adverts: lower not listed or sent, requests: lower not requested)
        uint16_t router : 1;   // The sending node is a router
        uint16_t : 3;          // Type-specific fields
        uint16_t : 6;          // Type-specific fields
        uint16_t : 2;          // Reserved for future use
    };
    struct {
        // Packet advertisement (REPLAY_TYPE_ADVERT_MAIN)
        uint16_t : 5;                // Common fields
        uint16_t router_only : 1;    // Only routers may request packet replay
        uint16_t favourite_only : 1; // Only favourites may request packet replay
        uint16_t boot : 1;           // This node rebooted recently
        uint16_t sequence : 5;       // Sequence number for this advertisement (0-31, wraps)
        uint16_t : 1;                // Unused
        uint16_t : 2;                // Common fields (reserved)
    };
    struct {
        // Purge advertisement (REPLAY_TYPE_ADVERT_PURGED)
        uint16_t : 5;           // Common fields
        uint16_t purge_all : 1; // This node has purged its entire cache
        uint16_t : 2;           // Unused
        uint16_t : 6;           // Unused
        uint16_t : 2;           // Common fields (reserved)
    };
    struct {
        // Broadcast stats (REPLAY_TYPE_ADVERT_STATS)
        uint16_t : 5;                      // Common fields
        uint16_t : 1; /* router_only */    // Same as packet advertisement
        uint16_t : 1; /* favourite_only */ // Same as packet advertisement
        uint16_t : 1;                      // Unused
        uint16_t req_priority : 2;         // Minimum priority packet for which this node will make requests
        uint16_t : 4;                      // Unused
        uint16_t : 2;                      // Common fields (reserved)
    };
    struct {
        // Packet request (REPLAY_TYPE_REQUEST_PACKETS)
        uint16_t : 5; // Common fields
        uint16_t : 3; // Unused
        uint16_t : 6; // Unused
        uint16_t : 2; // Common fields (reserved)
    };
    struct {
        // Stats request (REPLAY_TYPE_REQUEST_STATS)
        uint16_t : 5; // Common fields
        uint16_t : 3; // Unused
        uint16_t : 6; // Unused
        uint16_t : 2; // Common fields (reserved)
    };
} ReplayHeader __packed;
static_assert(sizeof(ReplayHeader) == sizeof(ReplayHeader::bitfield));

/**
 * Advertisement format
 * - header (2 bytes)
 * - packet count (5 bits per priority)
 * - packet hashes (2 bytes per packet, in priority order)
 * - throttled count (1 byte)
 * - throttled node numbers LSB (1 byte each)
 */

typedef struct ReplayEntry ReplayEntry;
struct ReplayEntry {
    ReplayHash hash = 0;
    union {
        uint8_t flags = 0;
        struct {
            uint8_t used : 1;        // This entry is in use
            uint8_t want_replay : 1; // This entry is pending replay
            uint8_t advertised : 1;  // We have advertised this packet to the mesh
            uint8_t opaque : 1;      // We couldn't decrypt this packet
            uint8_t priority : 2;    // Priority for replays of this packet
            uint8_t missing : 1;     // We have yet to receive this packet, but know it exists
            uint8_t gave_up : 1;     // We have given up trying to obtain this packet
        };
    };
    uint8_t replay_count = 0;
    meshtastic_MeshPacket *packet = {};
    ReplayEntry *next = NULL;
};

typedef struct ReplayMissing {
    ReplayHash hash = 0;
    unsigned long last_request_millis = 0;
    unsigned long discovered_millis = 0;
    union {
        uint32_t servers = 0;
        struct {
            NodeNum server_0 : 8;
            NodeNum server_1 : 8;
            NodeNum server_2 : 8;
            NodeNum server_3 : 8;
        };
    };
} ReplayMissing;

typedef struct ReplayServer {
    NodeNum id = 0;
    float last_snr = 0.0;
    unsigned long discovered_millis = 0;
    unsigned long last_advert_millis = 0;
    unsigned int adverts = 0;
    unsigned int packets = 0;
    unsigned int missed = 0;
    unsigned int requests = 0;
    unsigned int requested = 0;
    ReplayPriority last_priority = meshtastic_Config_ReplayConfig_ReplayPriority_BACKGROUND;
    union {
        uint8_t flags = 0;
        struct {
            uint8_t is_router : 1;
            uint8_t throttled : 1;
            uint8_t router_only : 1;
            uint8_t favourite_only : 1;
        };
    };
} ReplayServer;

class ReplayTable
{
  public:
    ReplayTable(meshtastic_ReplayStats *s) : stats(s) {}
    ReplayEntry *find(ReplayHash h);
    ReplayEntry *find(meshtastic_MeshPacket *p, bool strict = false);
    ReplayEntry *add(meshtastic_MeshPacket *p);
    ReplayEntry *add(ReplayHash h, ReplayPriority priority);
    meshtastic_MeshPacket *cache(ReplayEntry *e, meshtastic_MeshPacket *p);
    size_t getCacheCount() { return packet_cache_size; }
    size_t getCacheSize() { return sizeof(meshtastic_MeshPacket) * packet_cache_size; }
    size_t getQueueCount()
    {
        return std::count_if(std::begin(queue), std::end(queue), [](ReplayEntry *e) { return !!e; });
    }

  private:
    MemoryDynamic<meshtastic_MeshPacket> packet_cache{};
    size_t packet_cache_size = 0;
    ReplayEntry *queue[REPLAY_QUEUE_MAX]{};
    off_t queue_next = 0;
    ReplayEntry *buckets[REPLAY_HT_BUCKETS]{};
    ReplayEntry entry_pool[REPLAY_ENTRY_POOL_SIZE]{};
    off_t entry_pool_next = 0;
    meshtastic_ReplayStats *stats{};
    void add(ReplayEntry *e);
    void remove(ReplayEntry *e);
    void pruneCache(bool requested = false);
};

class ReplayModule : public SinglePortModule, private concurrency::NotifiedWorkerThread
{
  public:
    ReplayModule() : SinglePortModule("Replay", meshtastic_PortNum_REPLAY_APP), NotifiedWorkerThread("replay")
    {
        LOG_INFO("Replay: self_heap=%u replay_spacing=%u request_spacing=%u request_holdoff=%u", sizeof(*this),
                 REPLAY_SPACING(REPLAY_PACKET_SPACING), REPLAY_SPACING(REPLAY_PACKET_REQUEST_SPACING),
                 REPLAY_SPACING(REPLAY_PACKET_REQUEST_HOLDOFF));
        notify(REPLAY_NOTIFY_INIT, true);
    }
    static ReplayPriority replayPriority(meshtastic_MeshPacket *p);
    ReplayHash hash(meshtastic_MeshPacket *p) { return p ? REPLAY_HASH(p->from, p->id) : 0; }
    ReplayEntry *remember(meshtastic_MeshPacket *p);
    ReplayEntry *adopt(meshtastic_MeshPacket *p);
    void printStats(meshtastic_ReplayStats *s, NodeNum node, ReplayHeader *header = NULL);
    void printLocalStats();
    void sendLocalStats(NodeNum to = NODENUM_BROADCAST);
    void resetStats()
    {
        stats = {};
        stats_window_start_millis = millis();
    }
    void logRX(meshtastic_MeshPacket *p, unsigned int duration_ms);
    void logTX(meshtastic_MeshPacket *p, unsigned int duration_ms);
    void logRXBad() { stats.rx_packets_bad++; }
    void logTXDropped() { stats.tx_packets_dropped++; }
    void logTXDelayed() { stats.tx_packets_delayed++; }
    void logTXQueueDepth(unsigned int depth) { stats.tx_max_queue = depth > stats.tx_max_queue ? depth : stats.tx_max_queue; }
    void logReplayDropped() { stats.replay_dropped++; }

  private:
    meshtastic_ReplayStats stats{};
    ReplayTable table{&stats};
    uint32_t deadline = REPLAY_HOUSEKEEPING_MS;
    unsigned long stats_window_start_millis = 0;
    unsigned long next_stats_print_millis = REPLAY_STATS_PRINT_SECS * 1000;
    unsigned long next_stats_broadcast_millis =
        REPLAY_CFG(REPLAY_DEFAULT_STATS_BROADCAST_SECS, config.replay.stats_broadcast_secs) * 1000;
    unsigned long next_sequence = 0;
    ReplayHash advert[REPLAY_SEQUENCE_MASK + 1][REPLAY_ADVERT_PACKETS_MASK + 1]{};
    unsigned long advert_dirty[REPLAY_SEQUENCE_MASK + 1]{};
    unsigned long advert_pending = 0;
    unsigned long advert_last_millis = 0;
    unsigned long next_packet = 0;
    unsigned long last_replay_millis = 0;
    ReplayMissing missing[REPLAY_MISSING_MAX]{};
    off_t missing_next = 0;
    ReplayServer servers[REPLAY_SERVER_MAX]{};
    off_t server_next = 0;
    unsigned long last_housekeeping_millis = 0;
    void flushAdverts();
    void sendAdvert(off_t advert_idx);
    void onNotify(uint32_t notification) override;
    ProcessMessage handleReceived(const meshtastic_MeshPacket &p) override;
    void handlePacketAdvertisement(ReplayHeader *header, const unsigned char *data, size_t len, ReplayServer *server);
    void handleMissing(ReplayEntry *e, ReplayServer *via);
    void requestMissing();
    ReplayServer *findServer(NodeNum id, bool add = false);
    ReplayServer *findServer(uint8_t lsb);
};

extern ReplayModule *replayModule;