const std = @import("std");
const net = std.net;
const posix = std.posix;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

// --- WIRE FORMAT HELPERS ---

fn writeDomainName(writer: anytype, name: []const u8) !void {
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.LabelTooLong;
        try writer.writeByte(@intCast(label.len));
        try writer.writeAll(label);
    }
    try writer.writeByte(0);
}

/// Skips over a domain name in a DNS packet (handling RFC 1035 pointer compression)
fn skipName(packet: []const u8, offset: *usize) !void {
    while (offset.* < packet.len) {
        const len = packet[offset.*];
        if (len == 0) {
            offset.* += 1;
            return;
        } else if ((len & 0xC0) == 0xC0) {
            // It's a 16-bit pointer to elsewhere in the packet
            offset.* += 2;
            return;
        } else {
            // It's a standard length-prefixed label
            offset.* += len + 1;
        }
    }
    return error.PacketTooShort;
}

// --- TSIG KEY PARSER ---

pub const TsigKey = struct {
    name: []const u8,
    secret_base64: []const u8,
};

pub fn parseTsigKeyFile(allocator: std.mem.Allocator, file_path: []const u8) !TsigKey {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 8192);

    var key_name: ?[]const u8 = null;
    var secret: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, content, '\n');

    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (std.mem.startsWith(u8, line, "key ")) {
            const first_quote = std.mem.indexOfScalar(u8, line, '"') orelse continue;
            const rest = line[first_quote + 1 ..];
            const second_quote = std.mem.indexOfScalar(u8, rest, '"') orelse continue;
            key_name = rest[0..second_quote];
        }
        if (std.mem.indexOf(u8, line, "secret")) |_| {
            if (std.mem.indexOfScalar(u8, line, '"')) |first_quote| {
                const rest = line[first_quote + 1 ..];
                if (std.mem.indexOfScalar(u8, rest, '"')) |second_quote| {
                    secret = rest[0..second_quote];
                }
            }
        }
        if (std.mem.startsWith(u8, line, "Key:")) {
            secret = std.mem.trim(u8, line[4..], " \t\r");
        }
    }
    if (secret) |s| return TsigKey{ .name = key_name orelse "default-key.", .secret_base64 = s };
    return error.InvalidKeyFile;
}

// --- PACKET BUILDERS ---

fn buildSignedTxtUpdate(
    allocator: std.mem.Allocator,
    zone: []const u8,
    fqdn: []const u8,
    txt_value: []const u8,
    key_name: []const u8,
    raw_tsig_secret: []const u8,
    tx_id: u16,
) ![]u8 {
    if (txt_value.len > 255) return error.TxtValueTooLong;

    var msg = std.ArrayList(u8).init(allocator);
    const writer = msg.writer();

    try writer.writeInt(u16, tx_id, .big);
    try writer.writeInt(u16, 0x2800, .big);
    try writer.writeInt(u16, 1, .big); // ZOCOUNT
    try writer.writeInt(u16, 0, .big); // PRCOUNT
    try writer.writeInt(u16, 2, .big); // UPCOUNT
    try writer.writeInt(u16, 0, .big); // ARCOUNT (Must be 0 for digest)

    try writeDomainName(writer, zone);
    try writer.writeInt(u16, 6, .big); // ZTYPE SOA
    try writer.writeInt(u16, 1, .big); // ZCLASS IN

    // Delete old
    try writeDomainName(writer, fqdn);
    try writer.writeInt(u16, 16, .big); // TYPE TXT
    try writer.writeInt(u16, 255, .big); // CLASS ANY
    try writer.writeInt(u32, 0, .big);
    try writer.writeInt(u16, 0, .big);

    // Add new
    try writeDomainName(writer, fqdn);
    try writer.writeInt(u16, 16, .big); // TYPE TXT
    try writer.writeInt(u16, 1, .big);  // CLASS IN
    try writer.writeInt(u32, 60, .big);
    try writer.writeInt(u16, @intCast(txt_value.len + 1), .big);
    try writer.writeByte(@intCast(txt_value.len));
    try writer.writeAll(txt_value);

    // TSIG Digest
    const now: u64 = @intCast(std.time.timestamp());
    var tsig_payload = std.ArrayList(u8).init(allocator);
    const tsig_w = tsig_payload.writer();

    try tsig_w.writeAll(msg.items);
    try writeDomainName(tsig_w, key_name);
    try tsig_w.writeInt(u16, 255, .big);
    try tsig_w.writeInt(u32, 0, .big);
    try writeDomainName(tsig_w, "hmac-sha256.");
    try tsig_w.writeInt(u16, @intCast((now >> 32) & 0xFFFF), .big);
    try tsig_w.writeInt(u32, @intCast(now & 0xFFFFFFFF), .big);
    try tsig_w.writeInt(u16, 300, .big);
    try tsig_w.writeInt(u16, 0, .big);
    try tsig_w.writeInt(u16, 0, .big);

    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, tsig_payload.items, raw_tsig_secret);

    // Patch ARCOUNT to 1
    msg.items[10] = 0;
    msg.items[11] = 1;

    // Append TSIG RR
    try writeDomainName(writer, key_name);
    try writer.writeInt(u16, 250, .big); // TYPE TSIG
    try writer.writeInt(u16, 255, .big); // CLASS ANY
    try writer.writeInt(u32, 0, .big);
    try writer.writeInt(u16, 61, .big);  // Hardcoded hmac-sha256 len
    try writeDomainName(writer, "hmac-sha256.");
    try writer.writeInt(u16, @intCast((now >> 32) & 0xFFFF), .big);
    try writer.writeInt(u32, @intCast(now & 0xFFFFFFFF), .big);
    try writer.writeInt(u16, 300, .big);
    try writer.writeInt(u16, 32, .big);
    try writer.writeAll(&mac);
    try writer.writeInt(u16, tx_id, .big);
    try writer.writeInt(u16, 0, .big);
    try writer.writeInt(u16, 0, .big);

    return msg.toOwnedSlice();
}

fn buildTxtQuery(allocator: std.mem.Allocator, fqdn: []const u8, tx_id: u16) ![]u8 {
    var msg = std.ArrayList(u8).init(allocator);
    const writer = msg.writer();

    try writer.writeInt(u16, tx_id, .big);
    try writer.writeInt(u16, 0x0100, .big); // OpCode 0 (Query), RD flag
    try writer.writeInt(u16, 1, .big);      // QDCOUNT
    try writer.writeInt(u16, 0, .big);
    try writer.writeInt(u16, 0, .big);
    try writer.writeInt(u16, 0, .big);

    try writeDomainName(writer, fqdn);
    try writer.writeInt(u16, 16, .big); // TYPE TXT
    try writer.writeInt(u16, 1, .big);  // CLASS IN

    return msg.toOwnedSlice();
}

// --- NETWORK & PARSING ---

fn sendUdpPacket(server_ip: []const u8, packet: []const u8, expected_id: u16, op_name: []const u8, resp_buf: []u8) ![]const u8 {
    const srv_addr = try net.Address.parseIp4(server_ip, 53);
    const socket = try posix.socket(srv_addr.any.family, posix.SOCK.DGRAM, 0);
    defer posix.close(socket);

    const timeout = posix.timeval{ .tv_sec = 5, .tv_usec = 0 };
    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

    _ = try posix.sendto(socket, packet, 0, &srv_addr.any, srv_addr.getOsSockLen());

    const bytes_read = posix.recv(socket, resp_buf, 0) catch |err| {
        std.debug.print("{s} failed: Network error ({!})\n", .{op_name, err});
        std.process.exit(1);
    };

    if (bytes_read < 12) {
        std.debug.print("{s} failed: Packet too small\n", .{op_name});
        std.process.exit(1);
    }

    // FIX: strict pointer conversion [0..2]
    const resp_id = std.mem.readInt(u16, resp_buf[0..2][0..2], .big);
    if (resp_id != expected_id) {
        std.debug.print("{s} failed: Mismatched transaction ID\n", .{op_name});
        std.process.exit(1);
    }

    return resp_buf[0..bytes_read];
}

fn printTxtAnswers(packet: []const u8, qdcount: u16, ancount: u16) !void {
    var offset: usize = 12; // Skip header

    // Skip Question Section
    var i: u16 = 0;
    while (i < qdcount) : (i += 1) {
        try skipName(packet, &offset);
        if (offset + 4 > packet.len) return error.PacketTooShort;
        offset += 4; // Skip QTYPE and QCLASS
    }

    // Parse Answer Section
    i = 0;
    var found = false;
    while (i < ancount) : (i += 1) {
        try skipName(packet, &offset);
        if (offset + 10 > packet.len) return error.PacketTooShort;

        // FIX: strict pointer conversion [0..2]
        const rtype = std.mem.readInt(u16, packet[offset..][0..2], .big);
        const rdlength = std.mem.readInt(u16, packet[offset+8..][0..2], .big);
        offset += 10;

        if (offset + rdlength > packet.len) return error.PacketTooShort;

        if (rtype == 16) { // It's a TXT record
            found = true;
            var txt_offset = offset;
            const txt_end = offset + rdlength;

            std.debug.print("TXT: ", .{});
            while (txt_offset < txt_end) {
                const str_len = packet[txt_offset];
                txt_offset += 1;
                if (txt_offset + str_len > txt_end) return error.PacketTooShort;
                const text = packet[txt_offset .. txt_offset + str_len];
                std.debug.print("\"{s}\" ", .{text});
                txt_offset += str_len;
            }
            std.debug.print("\n", .{});
        }

        offset += rdlength;
    }

    if (!found) std.debug.print("No TXT records found.\n", .{});
}

// --- MAIN CLI ---

fn printUsage(exe_name: []const u8) void {
    std.debug.print("Usage:\n", .{});
    std.debug.print("  {s} lookup <fqdn> <server_ip>\n", .{exe_name});
    std.debug.print("  {s} update <zone> <fqdn> <txt_value> <key_name> <base64_secret> <server_ip>\n", .{exe_name});
    std.debug.print("  {s} update -k <key_file> <zone> <fqdn> <txt_value> <server_ip>\n", .{exe_name});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) {
        printUsage(args[0]);
        std.process.exit(1);
    }

    const mode = args[1];

    if (std.mem.eql(u8, mode, "lookup")) {
        if (args.len != 4) { printUsage(args[0]); std.process.exit(1); }
        const fqdn = args[2];
        const server_ip = args[3];

        var rand_bytes: [2]u8 = undefined;
        std.crypto.random.bytes(&rand_bytes);
        const tx_id = std.mem.readInt(u16, &rand_bytes, .big);

        const packet = try buildTxtQuery(allocator, fqdn, tx_id);

        var recv_buf: [2048]u8 = undefined;
        const resp = try sendUdpPacket(server_ip, packet, tx_id, "Lookup", &recv_buf);

        // FIX: strict pointer conversion [0..2]
        const flags = std.mem.readInt(u16, resp[2..][0..2], .big);
        const rcode = flags & 0x000F;

        if (rcode != 0) {
            std.debug.print("Lookup failed with RCODE: {d}\n", .{rcode});
            std.process.exit(1);
        }

        // FIX: strict pointer conversion [0..2]
        const qdcount = std.mem.readInt(u16, resp[4..][0..2], .big);
        const ancount = std.mem.readInt(u16, resp[6..][0..2], .big);

        try printTxtAnswers(resp, qdcount, ancount);

    } else if (std.mem.eql(u8, mode, "update")) {
        var zone: []const u8 = undefined;
        var fqdn: []const u8 = undefined;
        var txt_value: []const u8 = undefined;
        var key_name: []const u8 = undefined;
        var b64_secret: []const u8 = undefined;
        var server_ip: []const u8 = undefined;

        if (std.mem.eql(u8, args[2], "-k")) {
            if (args.len != 8) { printUsage(args[0]); std.process.exit(1); }
            const tsig_key = try parseTsigKeyFile(allocator, args[3]);
            zone = args[4];
            fqdn = args[5];
            txt_value = args[6];
            server_ip = args[7];
            key_name = tsig_key.name;
            b64_secret = tsig_key.secret_base64;
        } else {
            if (args.len != 8) { printUsage(args[0]); std.process.exit(1); }
            zone = args[2];
            fqdn = args[3];
            txt_value = args[4];
            key_name = args[5];
            b64_secret = args[6];
            server_ip = args[7];
        }

        const decoder = std.base64.standard.Decoder;
        const decoded_len = try decoder.calcSizeForSlice(b64_secret);
        const raw_secret = try allocator.alloc(u8, decoded_len);
        try decoder.decode(raw_secret, b64_secret);

        var rand_bytes: [2]u8 = undefined;
        std.crypto.random.bytes(&rand_bytes);
        const tx_id = std.mem.readInt(u16, &rand_bytes, .big);

        const packet = try buildSignedTxtUpdate(
            allocator, zone, fqdn, txt_value, key_name, raw_secret, tx_id
        );

        var recv_buf: [1024]u8 = undefined;
        const resp = try sendUdpPacket(server_ip, packet, tx_id, "Update", &recv_buf);

        // FIX: strict pointer conversion [0..2]
        const flags = std.mem.readInt(u16, resp[2..][0..2], .big);
        const rcode = flags & 0x000F;
        if (rcode == 0) {
            std.debug.print("Update successful! (RCODE: NOERROR)\n", .{});
        } else {
            std.debug.print("Update failed! RCODE: {d}\n", .{rcode});
            std.process.exit(1);
        }
    }
}
