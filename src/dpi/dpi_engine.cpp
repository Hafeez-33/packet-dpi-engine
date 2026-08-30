#include "dpi/dpi/dpi_engine.h"
#include "dpi/dpi/dns_parser.h"
#include "dpi/dpi/http_parser.h"
#include "dpi/dpi/tls_parser.h"
#include "dpi/flow/flow_types.h"

namespace dpi {

DpiResult DpiEngine::inspect(const ParsedPacket& packet) noexcept {
    if (!packet.is_valid() || packet.l7_payload.empty()) {
        return DpiResult{false, L7Metadata{}};
    }

    uint8_t proto = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    if (packet.is_tcp()) {
        proto = static_cast<uint8_t>(FlowProtocol::TCP);
        src_port = packet.tcp.src_port;
        dst_port = packet.tcp.dst_port;
    } else if (packet.is_udp()) {
        proto = static_cast<uint8_t>(FlowProtocol::UDP);
        src_port = packet.udp.src_port;
        dst_port = packet.udp.dst_port;
    }

    return inspect(packet.l7_payload, proto, src_port, dst_port);
}

DpiResult DpiEngine::inspect(std::string_view payload,
                            uint8_t protocol,
                            [[maybe_unused]] uint16_t src_port,
                            [[maybe_unused]] uint16_t dst_port) noexcept {
    if (payload.empty()) {
        return DpiResult{false, L7Metadata{}};
    }

    // 1. TCP Application Protocols
    if (protocol == static_cast<uint8_t>(FlowProtocol::TCP) || protocol == 6) {
        // A. Attempt TLS ClientHello detection
        TlsMetadata tls_meta;
        if (TlsParser::parse_client_hello(payload, tls_meta)) {
            DpiResult res;
            res.matched = true;
            res.metadata.protocol = AppProtocol::TLS;
            res.metadata.is_classified = true;
            res.metadata.tls = tls_meta;
            res.metadata.hostname = tls_meta.sni;
            res.metadata.details = tls_meta.has_sni ? ("TLS SNI: " + tls_meta.sni) : "TLS ClientHello";
            return res;
        }

        // B. Attempt HTTP/1.x Request detection
        HttpMetadata http_meta;
        if (HttpParser::parse_request(payload, http_meta)) {
            DpiResult res;
            res.matched = true;
            res.metadata.protocol = AppProtocol::HTTP;
            res.metadata.is_classified = true;
            res.metadata.http = http_meta;
            res.metadata.hostname = http_meta.host;
            res.metadata.details = http_meta.method + " " + http_meta.uri + " " + http_meta.version;
            return res;
        }
    }

    // 2. UDP Application Protocols (or Port 53)
    if (protocol == static_cast<uint8_t>(FlowProtocol::UDP) || protocol == 17 || src_port == 53 || dst_port == 53) {
        // Attempt DNS Question detection
        DnsMetadata dns_meta;
        if (DnsParser::parse_query(payload, dns_meta)) {
            DpiResult res;
            res.matched = true;
            res.metadata.protocol = AppProtocol::DNS;
            res.metadata.is_classified = true;
            res.metadata.dns = dns_meta;
            res.metadata.hostname = dns_meta.qname;
            res.metadata.details = "DNS Query: " + dns_meta.qname;
            return res;
        }
    }

    return DpiResult{false, L7Metadata{}};
}

} // namespace dpi
