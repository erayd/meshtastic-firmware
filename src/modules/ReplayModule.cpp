#include "ReplayModule.h"
#include "MeshService.h"
#include "airtime.h"
#include "memGet.h"
#include "meshUtils.h"
#include <numeric>

ReplayModule *replayModule = NULL;

/**
 * TODO:
 * - Remove v3 ignore list in handleReceived()
 * - Figure out why prune always prunes just one packet
 * - Implement token bucket throttling (count + LSB in ads)
 * - Implement replay count tracker for packets
 * - Implement favourite_only for handle missing & handle request
 * - Scale replay timing based on CWsize & chUtil
 * - Finish handlePacketAdvertisement()
 *   - Implement request for missing packets
 *   - Track last requested time, advertising node, stats
 * - Priority QoS
 *   - Based on how full the replay queue is?
 *   - Based on how long the oldest replay has been waiting?
 * - Add 'tailer' to rebroadcast packets, with a sequence number
 *   - Clients missing a number can request that it be replayed *immediately*
 *     - Clients should include recent hashes in the request, so we can avoid sending packets they already have
 *   - Alternative option: just include a list of recent hashes in the tailer (maybe truncated?)
 */

/**
 * Find a replay entry by its hash
 */
ReplayEntry *ReplayTable::find(ReplayHash h)
{
    for (ReplayEntry *e = buckets[REPLAY_BUCKET(h)]; e; e = e->next) {
        if (e->hash == h)
            return e;
    }
    return NULL;
}

/**
 * Find a replay entry by its packet (pointer equality if strict, otherwise by hash)
 */
ReplayEntry *ReplayTable::find(meshtastic_MeshPacket *p, bool strict)
{
    if (!p)
        return NULL;
    if (!strict)
        return find(REPLAY_HASH(p->from, p->id));
    for (ReplayEntry *e = buckets[REPLAY_BUCKET(REPLAY_HASH(p->from, p->id))]; e; e = e->next) {
        if (e->packet == p)
            return e;
    }
    return NULL;
}

/**
 * Add a packet to the replay table, returning the new entry
 */
ReplayEntry *ReplayTable::add(meshtastic_MeshPacket *p)
{
    if (!p)
        return NULL;
    ReplayHash hash = REPLAY_HASH(p->from, p->id);
    ReplayEntry *e = &entry_pool[entry_pool_next++ & REPLAY_ENTRY_POOL_MASK];
    if (e->used)
        remove(e);
    e->hash = hash;
    e->used = true;
    if (p->which_payload_variant != meshtastic_MeshPacket_decoded_tag)
        e->opaque = true; // We couldn't decrypt this packet
    e->priority = ReplayModule::replayPriority(p);

    add(e);
    return e;
}

/**
 * Add a hash to the replay table without having the packet
 */
ReplayEntry *ReplayTable::add(ReplayHash h, ReplayPriority priority)
{
    ReplayEntry *e = find(h);
    if (e)
        return e; // We already know about this packet
    e = &entry_pool[entry_pool_next++ & REPLAY_ENTRY_POOL_MASK];
    if (e->used)
        remove(e);
    e->hash = h;
    e->used = true;
    e->missing = true;
    e->priority = priority ? meshtastic_Config_ReplayConfig_ReplayPriority_HIGH
                           : meshtastic_Config_ReplayConfig_ReplayPriority_NORMAL; // Assume default priority
    add(e);
    return e;
}

/**
 * Add a packet to the cache
 */
meshtastic_MeshPacket *ReplayTable::cache(ReplayEntry *e, meshtastic_MeshPacket *p)
{
    if (!e || !p)
        return NULL;
    if (e->packet)
        return e->packet;                   // This packet is already cached
    e->packet = packet_cache.allocCopy(*p); // If the allocation fails, it will just behave as a pruned entry
    if (e->packet)
        packet_cache_size++;

    LOG_DEBUG("Replay: cache_packets=%u cache_bytes=%lu heap_avail=%lu heap_free=%lu", packet_cache_size,
              packet_cache_size * sizeof(meshtastic_MeshPacket),
              memGet.getFreeHeap() + (packet_cache_size * sizeof(meshtastic_MeshPacket)), memGet.getFreeHeap());

    pruneCache();
    return e->packet;
}

/**
 * Add an entry to the replay table
 */
void ReplayTable::add(ReplayEntry *e)
{
    ReplayEntry **target = &buckets[REPLAY_BUCKET(e->hash)];
    while (*target)
        target = &((*target)->next);
    e->used = true;
    e->next = NULL;
    *target = e;
}

/**
 * Remove an entry from the replay table
 */
void ReplayTable::remove(ReplayEntry *e)
{
    if (e->want_replay) {
        // Cancel pending replay
        e->want_replay = false;
        for (unsigned int i = 0; i < REPLAY_QUEUE_MAX; i++) {
            if (queue[i] == e) {
                queue[i] = NULL;
                stats->replay_dropped++;
            }
        }
    }
    if (e->packet) {
        // Drop the packet from the cache
        packet_cache.release(e->packet);
        packet_cache_size--;
    }
    *e = {};
    ReplayEntry **target = &buckets[REPLAY_BUCKET(e->hash)];
    while (*target) {
        if (*target == e) {
            *target = e->next;
            return;
        }
    }
    target = &((*target)->next);
}

/**
 * Prune the packet cache to keep it under the target memory limit
 */
void ReplayTable::pruneCache(bool requested)
{
    if (packet_cache_size <= REPLAY_CACHE_MIN)
        return; // Don't prune below the minimum cache size
    size_t current = getCacheSize();
    size_t available = memGet.getFreeHeap() + current;
    size_t target = available * (REPLAY_CACHE_MAX - REPLAY_CACHE_PRUNE) / 100;
    size_t to_free = (current - target) / sizeof(meshtastic_MeshPacket);
    if (current <= target || !to_free)
        return; // Nothing to do; we are already under the target
    LOG_INFO("Replay: Pruning oldest %u packets (%lu bytes) from the cache (target=%u current=%u)", to_free,
             to_free * sizeof(meshtastic_MeshPacket), target, current);
    for (off_t i = entry_pool_next + REPLAY_ENTRY_POOL_SIZE - 1; i > entry_pool_next; i--) {
        ReplayEntry *e = &entry_pool[i & REPLAY_ENTRY_POOL_MASK];
        if (e->packet && (requested || !e->want_replay)) {
            packet_cache.release(e->packet);
            e->packet = NULL;
            if (e->want_replay) {
                LOG_WARN("Replay: Pruning packet with outstanding replay request hash=0x%04x from=0x%08x id=0x%08x", e->hash,
                         e->packet->from, e->packet->id);
                e->want_replay = false;
                for (off_t j = 0; j < REPLAY_QUEUE_MAX; j++) {
                    if (queue[j] == e) {
                        queue[j] = NULL;
                        stats->replay_dropped++;
                    }
                }
            }
            packet_cache_size--;
            if (--to_free == 0)
                break;
        }
    }
    if (to_free) {
        // We couldn't free enough packets, so start nuking requested ones as well
        LOG_WARN("Replay: Pruning oldest %u packets with outstanding requests", to_free);
        pruneCache(true);
    }
}

/**
 * Determine a priority for a packet that we are tracking in the cache
 */
ReplayPriority ReplayModule::replayPriority(meshtastic_MeshPacket *p)
{
    ReplayPriority prio = meshtastic_Config_ReplayConfig_ReplayPriority_NORMAL;
    if (!p)
        return prio; // This isn't a packet

    if (p->which_payload_variant == meshtastic_MeshPacket_decoded_tag) {

        // Adjustments for decrypted packets
        if (p->decoded.portnum >= 64)
            prio = meshtastic_Config_ReplayConfig_ReplayPriority_LOW; // Non-core apps are assumed low priority by default
        // App-specific adjustments
        switch (p->decoded.portnum) {
        case meshtastic_PortNum_UNKNOWN_APP:          // Opaque app traffic, we don't understand it
        case meshtastic_PortNum_POSITION_APP:         // Position updates are frequent and automatic
        case meshtastic_PortNum_AUDIO_APP:            // Large payload, very inefficient, demote it to bottom of the heap
        case meshtastic_PortNum_IP_TUNNEL_APP:        // Potentially large source of traffic, it's abusive, demote it
        case meshtastic_PortNum_STORE_FORWARD_APP:    // Potentially large source of traffic, demote it
        case meshtastic_PortNum_RANGE_TEST_APP:       // These are zero-hop anyway
        case meshtastic_PortNum_TELEMETRY_APP:        // Frequent and automatic, demote it
        case meshtastic_PortNum_NEIGHBORINFO_APP:     // Automatic and repeated, reliability via redundancy rather than replay
        case meshtastic_PortNum_RETICULUM_TUNNEL_APP: // Potentially large source of foreign traffic, demote it
        case meshtastic_PortNum_CAYENNE_APP:          // LoRaWAN sensor data
        case _meshtastic_PortNum_MAX:                 // This isn't a real app, somebody probably screwed up, so deprioritise it
            prio = meshtastic_Config_ReplayConfig_ReplayPriority_BACKGROUND;
            break;
        case meshtastic_PortNum_NODEINFO_APP:   // Nodeinfo is repeated often and likely cached, so give way to other stuff:
        case meshtastic_PortNum_SERIAL_APP:     // Chatty, not as bad as IP
        case meshtastic_PortNum_TRACEROUTE_APP: // Meshsense gets abusive with this, demote despite potentially
                                                // human-initiated
        case meshtastic_PortNum_ATAK_PLUGIN:    // Can get very chatty, degrade gracefully by being more eager to drop this
        case meshtastic_PortNum_ATAK_FORWARDER: // Can get very chatty, degrade gracefully by being more eager to drop this
            prio = meshtastic_Config_ReplayConfig_ReplayPriority_LOW;
            break;
        case meshtastic_PortNum_REMOTE_HARDWARE_APP:  // Some user likely cares about this, especially if it's for HW control
        case meshtastic_PortNum_ROUTING_APP:          // Routing packets matter, but are secondary to priority user traffic
        case meshtastic_PortNum_DETECTION_SENSOR_APP: // Event-triggered, it matters but not as much as human-initiated stuff
        case meshtastic_PortNum_REPLY_APP:            // Likely human-initiated, but it's just a ping
        case meshtastic_PortNum_PAXCOUNTER_APP:       // Event-triggered, it matters but not as much as human-initiated stuff
        case meshtastic_PortNum_REPLAY_APP:           // Anything from the replay module that's important is sent zero-hop
        case meshtastic_PortNum_POWERSTRESS_APP:      // Seems like a temporary thing that a human will care about
        case meshtastic_PortNum_PRIVATE_APP:          // Something bespoke, leave it alone
            prio = meshtastic_Config_ReplayConfig_ReplayPriority_NORMAL;
            break;
        case meshtastic_PortNum_ADMIN_APP:        // Remote admin is critical
        case meshtastic_PortNum_TEXT_MESSAGE_APP: // Text messages are important
        case meshtastic_PortNum_TEXT_MESSAGE_COMPRESSED_APP:
        case meshtastic_PortNum_WAYPOINT_APP: // Explicitly user-initiated and often important for a group to reliably RX
        case meshtastic_PortNum_ALERT_APP:
        case meshtastic_PortNum_KEY_VERIFICATION_APP: // If this breaks, DMs won't work properly
            prio = meshtastic_Config_ReplayConfig_ReplayPriority_HIGH;
            break;
        default:
            break; // Don't adjust priority for apps not explicitly handled above
        }

        /**
         * Apps not specifically given a priority:
         *   ZPS_APP - I don't know enough about it to have an opinion
         *   SIMULATOR_APP - I don't know enough about it to have an opinion
         *   MAP_REPORT_APP - I don't know enough about it to have an opinion
         *
         */

        if (prio > meshtastic_Config_ReplayConfig_ReplayPriority_BACKGROUND && p->to != NODENUM_BROADCAST &&
            (p->decoded.want_response || p->want_ack))
            prio = meshtastic_Config_ReplayConfig_ReplayPriority_HIGH; // Unicast messages that want a response are important
                                                                       // unless from a backgrounded app
    } else {
        // Adjustments for packets we can't decrypt
        if (p->to != NODENUM_BROADCAST) {
            if (p->want_ack)
                // ACK-wanted unicast packets are clearly more important
                prio = meshtastic_Config_ReplayConfig_ReplayPriority_HIGH;
            else
                // Assume that unicast stuff has a human who wants it to arrive
                prio = meshtastic_Config_ReplayConfig_ReplayPriority_NORMAL;
        } else {
            if (p->want_ack)
                // ACK-wanted broadcasts likely matter, but are untargeted
                prio = meshtastic_Config_ReplayConfig_ReplayPriority_NORMAL;
            else
                // Broadcast and no ACK is fire-and-forget
                prio = meshtastic_Config_ReplayConfig_ReplayPriority_LOW;
        }
    }

    return prio;
}

/**
 * Remember a packet in the replay table
 */
ReplayEntry *ReplayModule::remember(meshtastic_MeshPacket *p)
{
    if (!p || !config.replay.enabled)
        return NULL;
    ReplayEntry *e = table.find(p);
    if (e)
        return e; // We already know about this packet
    LOG_DEBUG("Replay: Remember packet hash=0x%04x from=0x%08x id=0x%08x", e->hash, p->from, p->id);
    e = table.add(p);
    e->priority = replayPriority(p);
    return e;
}

/**
 * Adopt a packet into the replay table (making a copy for the cache)
 */
ReplayEntry *ReplayModule::adopt(meshtastic_MeshPacket *p)
{
    if (!p || !p->hop_limit || !config.replay.enabled)
        return NULL;
    ReplayEntry *e = table.find(p, true);
    if (!e)
        e = table.add(p);
    e->priority = replayPriority(p);
    if (!e->packet && e->priority >= config.replay.min_cache_priority) {
        LOG_DEBUG("Replay: Adopt packet hash=0x%04x from=0x%08x id=0x%08x", e->hash, p->from, p->id);
        if (table.cache(e, p)) {
            off_t advert_idx = (next_packet >> __builtin_popcount(REPLAY_ADVERT_PACKETS_MASK)) & REPLAY_SEQUENCE_MASK;
            off_t packet_idx = next_packet & REPLAY_ADVERT_PACKETS_MASK;
            LOG_DEBUG("Replay: Setting advert[%u][%u] = 0x%04x", advert_idx, packet_idx, e->hash);
            advert_pending |= 1UL << advert_idx;
            advert_dirty[advert_idx] |= 1UL << packet_idx;
            advert[advert_idx][packet_idx] = e->hash;
            if ((next_packet & REPLAY_ADVERT_PACKETS_MASK) + 1 >=
                REPLAY_CFG(REPLAY_DEFAULT_FLUSH_PACKETS, config.replay.flush_packets)) {
                if (next_packet++)
                    next_packet = (next_packet & ~REPLAY_ADVERT_PACKETS_MASK) + REPLAY_ADVERT_PACKETS_MASK + 1;
                notify(REPLAY_NOTIFY_FLUSH, true);
            } else
                next_packet++;
        }
    }
    return e;
}

/**
 * Print replay stats for the current window
 */
void ReplayModule::printStats(meshtastic_ReplayStats *s, NodeNum node, ReplayHeader *header)
{
    bool local = node == nodeDB->getNodeNum();
    LOG_INFO("Replay: Stats for node 0x%08x%s, last %u seconds", node, local ? " (myself)" : "", s->window_length_secs);
    LOG_INFO("  RX: unique=%u duplicate=%u xh=%u bad=%u eol=%u local=%u zero=%u", s->rx_packets_unique, s->rx_packets_duplicate,
             s->rx_packets_duplicate_xh, s->rx_packets_bad, s->rx_packets_eol, s->rx_packets_local, s->rx_packets_zero);
    LOG_INFO("  TX: mine=%u rebroadcast=%u dropped=%u delayed=%u queue_max=%u", s->tx_packets_mine, s->tx_packets_relay,
             s->tx_packets_dropped, s->tx_packets_delayed, s->tx_max_queue);
    LOG_INFO("  Airtime: rx=%ums tx=%ums replay=%ums chutil=%4.2f", s->rx_ms, s->tx_ms, 0, airTime->channelUtilizationPercent());
    LOG_INFO("  Replay: p0=%u/%u p1=%u/%u p2=%u/%u p3=%u/%u queue_max=%u cached=%u cache_misses=%u missed=%u gave_up=%u ads=%u",
             s->tx_packets_p0, s->tx_packets_p0_skipped, s->tx_packets_p1, s->tx_packets_p1_skipped, s->tx_packets_p2,
             s->tx_packets_p2_skipped, s->tx_packets_p3, s->tx_packets_p3_skipped, s->replay_max_queue, s->cached,
             s->cache_misses, s->missed, s->gave_up, s->adverts_sent);
    if (header)
        LOG_INFO("  Config: prio=%u router=%u router_only=%u fav_only=%u req_prio=%u", header->priority, header->router,
                 header->router_only, header->favourite_only, header->req_priority);
    if (local)
        LOG_INFO("  Heap: avail=%lu free=%lu cache=%lu cache_packets=%u", memGet.getFreeHeap() + table.getCacheSize(),
                 memGet.getFreeHeap(), table.getCacheSize(), table.getCacheCount());
}

/**
 * Print local stats and reset the window
 */
void ReplayModule::printLocalStats()
{
    ReplayHeader h{};
    h.type = REPLAY_TYPE_ADVERT_STATS;
    h.priority = config.replay.min_request_priority;
    h.router = IS_ONE_OF(config.device.role, meshtastic_Config_DeviceConfig_Role_ROUTER,
                         meshtastic_Config_DeviceConfig_Role_ROUTER_LATE);
    h.router_only = config.replay.requests_routers_only;
    h.favourite_only = config.replay.requests_favourites_only;
    h.req_priority = config.replay.min_request_priority;

    stats.window_length_secs = (millis() - stats_window_start_millis) / 1000;
    stats.cached = table.getCacheCount();
    next_stats_print_millis = millis() + REPLAY_STATS_PRINT_SECS * 1000;
    printStats(&stats, nodeDB->getNodeNum(), &h);
}

/**
 * Send local stats as a replay packet
 */
void ReplayModule::sendLocalStats(NodeNum to)
{
    stats.window_length_secs = (millis() - stats_window_start_millis) / 1000;
    stats.cached = table.getCacheCount();

    LOG_INFO("Replay: Sending local stats to the mesh");
    ReplayHeader header{};
    header.type = REPLAY_TYPE_ADVERT_STATS;
    header.priority = config.replay.min_request_priority;
    header.router = IS_ONE_OF(config.device.role, meshtastic_Config_DeviceConfig_Role_ROUTER,
                              meshtastic_Config_DeviceConfig_Role_ROUTER_LATE);
    header.router_only = config.replay.requests_routers_only;
    header.favourite_only = config.replay.requests_favourites_only;
    header.req_priority = config.replay.min_request_priority;

    meshtastic_MeshPacket *p = allocDataPacket();
    if (!p) {
        LOG_WARN("Replay: Unable to allocate packet for local stats");
        return;
    }
    p->to = to;
    p->decoded.portnum = meshtastic_PortNum_REPLAY_APP;
    p->priority = meshtastic_MeshPacket_Priority_DEFAULT; // Don't use the main replay priority for stats

    unsigned char *pos = p->decoded.payload.bytes;
    memcpy(pos, &header, sizeof(header));
    pos += sizeof(header);
    pos += pb_encode_to_bytes(pos, sizeof(p->decoded.payload.bytes) - (pos - p->decoded.payload.bytes),
                              meshtastic_ReplayStats_fields, &stats);
    p->decoded.payload.size = pos - p->decoded.payload.bytes;

    if (to == NODENUM_BROADCAST) {
        next_stats_broadcast_millis =
            millis() + REPLAY_CFG(REPLAY_DEFAULT_STATS_BROADCAST_SECS, config.replay.stats_broadcast_secs) * 1000;
        resetStats();
    }
    service->sendToMesh(p);
}
/**
 * Log a received packet prior to processing
 */
void ReplayModule::logRX(meshtastic_MeshPacket *p, unsigned int duration_ms)
{
    stats.rx_ms += duration_ms;

    ReplayEntry *e = table.find(p);
    if (e) {
        if (e->missing)
            e->missing = false; // We have it now, so don't ask for replays
        else {
            stats.rx_packets_duplicate++;
            if (e->packet && p->hop_limit > e->packet->hop_limit)
                stats.rx_packets_duplicate_xh++;
            return; // Don't log any other stats for duplicate packets
        }
    }

    stats.rx_packets_unique++;
    if (!p->hop_limit) {
        if (!p->hop_start)
            stats.rx_packets_zero++;
        else
            stats.rx_packets_eol++;
    } else if (p->hop_limit == p->hop_start) {
        stats.rx_packets_local++;
    }
}

/**
 * Log a transmitted packet
 */
void ReplayModule::logTX(meshtastic_MeshPacket *p, unsigned int duration_ms)
{
    if (isFromUs(p))
        stats.tx_packets_mine++;
    else
        stats.tx_packets_relay++;
    stats.tx_ms += duration_ms;
}

/**
 * Send any pending advertisements
 */
void ReplayModule::flushAdverts()
{
    if (!advert_dirty)
        return; // Nothing pending
    next_packet = (next_packet & ~REPLAY_ADVERT_PACKETS_MASK) + REPLAY_ADVERT_PACKETS_MASK + 1;
    unsigned int prio_count[4] = {};
    for (off_t advert_idx = 0; advert_idx <= REPLAY_SEQUENCE_MASK; advert_idx++) {
        if (!(advert_pending & (1UL << advert_idx)))
            continue;
        if (!advert_dirty[advert_idx]) {
            advert_pending &= ~(1UL << advert_idx);
            continue;
        }
        sendAdvert(advert_idx);
    }
}

void ReplayModule::sendAdvert(off_t advert_idx)
{
    ReplayHeader header{};
    header.type = REPLAY_TYPE_ADVERT_MAIN;
    header.priority = config.replay.min_cache_priority;
    header.router = IS_ONE_OF(config.device.role, meshtastic_Config_DeviceConfig_Role_ROUTER,
                              meshtastic_Config_DeviceConfig_Role_ROUTER_LATE);
    header.router_only = config.replay.requests_routers_only;
    header.favourite_only = config.replay.requests_favourites_only;
    header.boot =
        next_packet & ~(REPLAY_SEQUENCE_MASK << __builtin_popcount(REPLAY_ADVERT_PACKETS_MASK) | REPLAY_ADVERT_PACKETS_MASK);
    header.sequence = advert_idx;

    meshtastic_MeshPacket *p = allocDataPacket();
    unsigned char *pos = p->decoded.payload.bytes;
    memcpy(pos, &header, sizeof(header));
    pos += sizeof(header);
    unsigned int prio_count[4] = {};
    unsigned char *prio_pos = pos;
    size_t prio_len = (unsigned char[]){3, 3, 2, 1}[header.priority]; // Leave space for priority counts
    pos += prio_len;

    for (unsigned int prio = header.priority; prio <= meshtastic_Config_ReplayConfig_ReplayPriority_HIGH; prio++) {
        for (off_t packet_idx = 0; packet_idx <= REPLAY_ADVERT_PACKETS_MASK; packet_idx++) {
            if (!(advert_dirty[advert_idx] & (1UL << packet_idx)))
                continue;
            ReplayHash h = advert[advert_idx][packet_idx];
            ReplayEntry *e = table.find(h);
            if (!e && prio == meshtastic_Config_ReplayConfig_ReplayPriority_HIGH) {
                stats.cache_misses++;
                continue;
            }
            if (e->priority != prio)
                continue;
            if (!e->packet) {
                stats.cache_misses++;
                continue;
            }
            LOG_DEBUG("Replay: Advertising packet hash=0x%04x from=0x%08x id=0x%08x prio=%u", h, e->packet->from, e->packet->id,
                      e->priority);
            memcpy(pos, &h, sizeof(h));
            pos += sizeof(h);
            prio_count[prio]++;
            e->advertised = true;
        }
    }

    unsigned int prio_count_encoded = 0;
    for (unsigned int prio = header.priority; prio <= meshtastic_Config_ReplayConfig_ReplayPriority_HIGH; prio++)
        prio_count_encoded = (prio_count_encoded << 5) | (prio_count[prio] & 0x1F);
    memcpy(prio_pos, &prio_count_encoded, prio_len);

    p->decoded.payload.size = pos - p->decoded.payload.bytes;
    p->to = NODENUM_BROADCAST;
    p->hop_limit = 0;
    p->priority = REPLAY_PRIORITY;

    advert_pending &= ~(1UL << advert_idx);
    advert_last_millis = millis();
    stats.adverts_sent++;
    service->sendToMesh(p);

    LOG_INFO("Replay: Sent broadcast advertisement seq=%u packets=%u prio=%u p0=%u p1=%u p2=%u p3=%u boot=%u", advert_idx,
             std::accumulate(prio_count, std::end(prio_count), 0), header.priority, prio_count[0], prio_count[1], prio_count[2],
             prio_count[3], header.boot);
}

void ReplayModule::onNotify(uint32_t notification)
{
    if (!config.replay.enabled) {
        LOG_INFO("Replay: Disabled, ignoring notification %u", notification);
        return;
    }

    if (notification == REPLAY_NOTIFY_MISSING)
        requestMissing();

    unsigned int now = millis();

    // Print stats
    if (now >= next_stats_print_millis)
        printLocalStats();

    // Send stats
    if (now >= next_stats_broadcast_millis)
        sendLocalStats();

    if (advert_pending && (notification == REPLAY_NOTIFY_FLUSH ||
                           now >= advert_last_millis + REPLAY_CFG(REPLAY_DEFAULT_FLUSH_SECS, config.replay.flush_secs) * 1000))
        flushAdverts();

    if (last_housekeeping_millis + REPLAY_HOUSEKEEPING_MS <= now) {
        last_housekeeping_millis = now;
        for (off_t i = 0; i < REPLAY_MISSING_MAX; i++) {
            if (!missing[i].discovered_millis)
                continue; // Not in use
            ReplayEntry *e = table.find(missing[i].hash);
            if (!e || !e->missing || missing[i].discovered_millis + REPLAY_MISSING_GIVEUP_SECS * 1000 < now) {
                // We either have this or no longer care about it
                if (!e || e->missing) {
                    LOG_WARN("Replay: Giving up on missing packet hash=0x%04x", missing[i].hash);
                    stats.gave_up++;
                    if (e)
                        e->gave_up = true;
                }
                missing[i] = {};
                continue;
            }
        }
    }

    // Sleep until the next deadline
    if (deadline <= now)
        deadline = now + REPLAY_INTERVAL_MS;
    notifyLater(deadline - now, REPLAY_NOTIFY_INTERVAL, true);
    return;
}

/**
 * Handle incoming packets
 */
ProcessMessage ReplayModule::handleReceived(const meshtastic_MeshPacket &p)
{
    if (p.from == 0x6da1c89c || p.from == 0x92ab4432 || p.from == 0xb66a32ae || p.from == 0xd9bd1c27 || p.from == 0x60a8f8d1) {
        LOG_INFO("Ignoring replay packet from known v3 node 0x%08x", p.from);
        return ProcessMessage::STOP;
    }
    if (p.from == nodeDB->getNodeNum())
        return ProcessMessage::STOP; // Ignore packets from our own node
    if (p.decoded.payload.size < sizeof(ReplayHeader))
        return ProcessMessage::STOP; // Too short for the header

    const unsigned char *pos = p.decoded.payload.bytes;
    ReplayHeader header{};
    memcpy(&header, pos, sizeof(header));
    pos += sizeof(header);

    if (p.to == NODENUM_BROADCAST) {
        // Incoming broadcasts
        switch (header.type) {
        case REPLAY_TYPE_ADVERT_MAIN: {
            ReplayServer *server = findServer(p.from, true);
            server->last_advert_millis = millis();
            server->last_priority = header.priority;
            server->is_router = header.router;
            server->router_only = header.router_only;
            server->favourite_only = header.favourite_only;
            server->last_snr = p.rx_snr;
            handlePacketAdvertisement(&header, pos, p.decoded.payload.size - (pos - p.decoded.payload.bytes), server);
        } break;
        case REPLAY_TYPE_ADVERT_PURGED:
            LOG_WARN("Replay: Purged adverts not yet implemented");
            break;
        case REPLAY_TYPE_ADVERT_STATS: {
            meshtastic_ReplayStats stats{};
            if (pb_decode_from_bytes(pos, p.decoded.payload.size - (pos - p.decoded.payload.bytes), meshtastic_ReplayStats_fields,
                                     &stats)) {
                printStats(&stats, p.from);
            } else {
                LOG_WARN("Replay: Failed to decode stats broadcast from 0x%08x", p.from);
            }
            break;
        }
            LOG_WARN("Replay: Stats adverts not yet implemented");
            break;
        }
    } else if (p.to == nodeDB->getNodeNum()) {
        // Requests for this node
        switch (header.type) {
        case REPLAY_TYPE_REQUEST_PACKETS:
            LOG_WARN("Replay: Packet requests not yet implemented");
            break;
        case REPLAY_TYPE_REQUEST_STATS:
            sendLocalStats(p.from);
            break;
        }
        return ProcessMessage::STOP; // This is for somebody else
    }

    return ProcessMessage::STOP; // All done
}

/**
 * Handle an incoming packet advertisement
 */
void ReplayModule::handlePacketAdvertisement(ReplayHeader *header, const unsigned char *data, size_t data_len,
                                             ReplayServer *server)
{
    size_t prio_len = (unsigned char[]){3, 3, 2, 1}[header->priority];
    if (data_len < prio_len)
        return; // Too short to be valid
    unsigned int prio_count_encoded = 0;
    memcpy(&prio_count_encoded, data, prio_len);
    data += prio_len;
    unsigned int prio_count[4] = {};
    for (unsigned int prio = header->priority; prio <= meshtastic_Config_ReplayConfig_ReplayPriority_HIGH; prio++)
        prio_count[prio] = prio_count_encoded >> (5 * (3 - (prio - header->priority))) & 0x1F;
    unsigned int packet_count = std::accumulate(prio_count, std::end(prio_count), 0);
    size_t expected_len = prio_len + packet_count * sizeof(ReplayHash);
    if (data_len < expected_len) {
        LOG_WARN("Replay: Advert body from 0x%08x too short (len=%u expected=%u)", server->id, data_len, expected_len);
        return;
    }
    server->adverts++;

    bool shouldNotify = false;
    for (ReplayPriority prio = header->priority; prio <= meshtastic_Config_ReplayConfig_ReplayPriority_HIGH; prio++) {
        for (unsigned int i = 0; i < prio_count[prio]; i++) {
            ReplayHash h{};
            memcpy(&h, data, sizeof(h));
            data += sizeof(h);
            ReplayEntry *e = table.find(h);
            if (!e) {
                LOG_WARN("Replay: Discovered missing packet hash=0x%04x prio=%u via=0x%08x", h, prio, server->id);
                e = table.add(h, prio);
                stats.missed++;
                handleMissing(e, server);
                shouldNotify = true;
            } else if (e->missing) {
                // We already know we are missing this packet, but we now know that this host still has it available
                LOG_WARN("Replay: Still missing packet hash=0x%04x prio=%u via=0x%08x", h, prio, server->id);
                handleMissing(e, server);
                shouldNotify = true;
            } else {
                // We already have this packet, nothing to do
                LOG_DEBUG("Replay: Discovered known packet hash=0x%04x prio=%u via=0x%08x", h, prio, server->id);
            }
        }
    }

    if (shouldNotify)
        notify(REPLAY_NOTIFY_MISSING, true);
}

/**
 * Handle a missing packet
 */
void ReplayModule::handleMissing(ReplayEntry *e, ReplayServer *via)
{
    if (!e || !e->missing || e->gave_up)
        return; // Nothing to do

    ReplayMissing *m{};
    for (off_t i = 0; i < REPLAY_MISSING_MAX; i++) {
        if (missing[i].hash == e->hash) {
            m = &missing[i];
            break;
        }
    }
    if (!m) {
        // We aren't tracking this yet, so find a free slot
        for (off_t i = 0; i < REPLAY_MISSING_MAX; i++) {
            if (!missing[i].discovered_millis) {
                // Unused slot
                m = &missing[i];
                break;
            }
            ReplayEntry *me = table.find(missing[i].hash);
            if (!me || !me->missing || me->gave_up) {
                // This slot is stale and can be taken over
                m = &missing[i];
                break;
            }
            if (missing[i].discovered_millis + REPLAY_MISSING_GIVEUP_SECS * 1000 < millis()) {
                // This slot is old enough to be forgotten
                LOG_WARN("Replay: Giving up on missing packet hash=0x%04x", missing[i].hash);
                me->gave_up = true;
                stats.gave_up++;
                m = &missing[i];
                break;
            }
        }
        if (!m) {
            // Too many outstanding missing packets; replace the oldest
            off_t oldest = 0;
            for (off_t i = 0; i < REPLAY_MISSING_MAX; i++) {
                if (missing[i].discovered_millis < missing[oldest].discovered_millis)
                    oldest = i;
            }
            LOG_WARN("Replay: Giving up on missing packet hash=0x%04x", missing[oldest].hash);
            ReplayEntry *me = table.find(missing[oldest].hash);
            if (me)
                me->gave_up = true;
            stats.gave_up++;
            m = &missing[oldest];
        }

        *m = {};
        m->hash = e->hash;
        m->discovered_millis = millis();
    }

    uint8_t lsb = via->id & 0xFF;
    if (m->server_0 != lsb && m->server_1 != lsb && m->server_2 != lsb && m->server_3 != lsb) {
        m->servers <<= 8;
        m->servers |= lsb;
    }
}

/**
 * Request any missing packets
 */
void ReplayModule::requestMissing()
{
    ReplayServer *local_servers[256] = {};
    for (ReplayServer *s = servers; s < std::end(servers); s++) {
        if (s->id)
            local_servers[s->id & 0xFF] = s;
    }
    unsigned int re_request_delay_ms = REPLAY_SPACING(REPLAY_PACKET_REQUEST_SPACING);
    unsigned int holdoff_ms = REPLAY_SPACING(REPLAY_PACKET_REQUEST_HOLDOFF);
    unsigned int now = millis();
    bool am_router = IS_ONE_OF(config.device.role, meshtastic_Config_DeviceConfig_Role_ROUTER,
                               meshtastic_Config_DeviceConfig_Role_ROUTER_LATE);
    ReplayServer *packet_servers[REPLAY_MISSING_MAX] = {};
    for (off_t i = 0; i < REPLAY_MISSING_MAX; i++) {
        ReplayMissing *m = &missing[i];
        if (!m->discovered_millis || m->discovered_millis + holdoff_ms > now)
            continue; // Not in use or too early to request
        if (m->last_request_millis + re_request_delay_ms > now)
            continue; // Too soon to re-request
        // TODO: Priority QoS
        for (off_t j = 0; j < 4; j++) {
            ReplayServer *s = local_servers[m->servers >> (j * 8) & 0xFF];
            if (!s)
                continue; // We don't know about this server
            if (s->throttled)
                continue; // This server is throttled
            if (s->router_only && !am_router)
                continue; // This server is router-only and we're not a router
            if (!packet_servers[i] || packet_servers[i]->last_snr < s->last_snr)
                packet_servers[i] = s; // Prefer the server with the best SNR
        }
    }
    for (ReplayServer *s = servers; s < std::end(servers); s++) {
        unsigned int packets = std::count_if(packet_servers, std::end(packet_servers), [s](ReplayServer *x) { return x == s; });
        ReplayHeader header{};
        header.type = REPLAY_TYPE_REQUEST_PACKETS;
        header.priority = config.replay.min_request_priority;
        header.router = am_router;
        // TODO assemble the packet
    }

    // TODO: Implement this
    // - Lookup table of lsb -> servers (256 entries on stack) DONE
    // - Pick server with best SNR for each packet DONE
    // - Dispatch requests
    // - Listen to other people requesting the same packet from a server we know we can hear, and don't ask for it ourselves
    // - Make a note of which server we asked last time, so if it isn't fulfilled we can try a different one
}

/**
 * Find a replay server
 */
ReplayServer *ReplayModule::findServer(NodeNum id, bool add)
{
    for (ReplayServer *s = servers; s < std::end(servers); s++) {
        if (s->id == id)
            return s;
    }
    if (add) {
        unsigned long now = millis();
        ReplayServer *target = servers;
        for (ReplayServer *s = servers; s < std::end(servers); s++) {
            if (!s->id) {
                // Empty slot
                target = s;
                break;
            }
            if (s->last_advert_millis + REPLAY_SERVER_TIMEOUT_SECS * 1000 < millis()) {
                LOG_INFO("Replay: Forgetting stale server 0x%08x (router=%u throttled=%u snr=%4.2f prio=%u ads=%u missed=%u "
                         "reqs=%u reqd=%u)",
                         s->id, s->is_router, s->throttled, s->last_snr, s->last_priority, s->adverts, s->missed, s->requests,
                         s->requested);
                target = s;
                break;
            }
            if (!target->is_router && s->is_router)
                target = s; // Prefer routers
            else if ((target->is_router == s->is_router) && target->last_snr < s->last_snr)
                target = s; // Prefer better SNR
            else if ((target->is_router == s->is_router) && (target->last_snr == s->last_snr) &&
                     target->last_advert_millis < s->last_advert_millis)
                target = s; // Prefer more recently heard
        }
        *target = {};
        target->id = id;
        target->discovered_millis = now;
        return target;
    }
    return NULL;
}

/**
 * Find a replay server by node ID LSB
 */
ReplayServer *ReplayModule::findServer(uint8_t lsb)
{
    for (ReplayServer *s = servers; s < std::end(servers); s++) {
        if (s->id && (s->id & 0xFF) == lsb)
            return s;
    }
    return NULL;
}