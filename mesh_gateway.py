#!/usr/bin/env python3
import os
import time
import json
import queue
import types
import sqlite3
from datetime import datetime

import meshtastic
import meshtastic.serial_interface
from pubsub import pub

from flask import (
    Flask,
    jsonify,
    send_from_directory,
    Response,
    request,
)

# ===========================================================
#  STATIC CHANNEL CONFIG  (can be upgraded later from packets)
# ===========================================================
last_config = None

CHANNELS = [
    {
        "id": 0,
        "index": 0,
        "primary": True,
        "psk": "AQ==",  # default PSK
        "name": "",     # unnamed primary
        "uplinkEnabled": False,
        "downlinkEnabled": False,
        "moduleSettings": {
            "positionPrecision": 15,
            "isClientMuted": False,
        },
    },
    {
        "id": 1,
        "index": 1,
        "primary": False,
        "psk": "7kKK1CDLFctybEA7nM/vxQ==",  # SierraGolf PSK (encrypted)
        "name": "SierraGolf",
        "uplinkEnabled": True,
        "downlinkEnabled": True,
        "moduleSettings": {
            "positionPrecision": 10,
            "isClientMuted": False,
        },
    },
]

# ===========================================================
#  GLOBALS
# ===========================================================
SERIAL_PORT = "/dev/ttyACM0"
DB = "packets.db"

app = Flask(__name__)
interface = None  # set in main()
sse_queue: "queue.Queue[dict]" = queue.Queue()


# ===========================================================
#  JSON SANITIZER
# ===========================================================
def sanitize_for_json(obj):
    """
    Recursively convert anything (mappingproxy, protobuf-ish objects, bytes)
    into JSON-safe Python structures (dict/list/str/...).
    """
    # Simple JSON-safe types
    if obj is None or isinstance(obj, (int, float, str, bool)):
        return obj

    # bytes → utf-8 string (lossy OK)
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)

    # mappingproxy → dict
    if isinstance(obj, types.MappingProxyType):
        return {k: sanitize_for_json(v) for k, v in obj.items()}

    # dict
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}

    # list / tuple / set
    if isinstance(obj, (list, tuple, set)):
        return [sanitize_for_json(x) for x in obj]

    # generic object with __dict__
    if hasattr(obj, "__dict__"):
        return sanitize_for_json(obj.__dict__)

    # final fallback
    return str(obj)


# ===========================================================
#  DATABASE
# ===========================================================
def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            from_label TEXT,
            to_id TEXT,
            message TEXT,
            raw_json TEXT,
            channel INTEGER
        )
        """
    )
    conn.commit()
    conn.close()


def save_packet(packet: dict):
    """
    Save a Meshtastic packet into SQLite, with a human-ish message string.
    """
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    ts = datetime.now().isoformat()

    from_num = packet.get("from")
    to_num = packet.get("to")
    from_id = packet.get("fromId") or str(from_num)
    to_id = packet.get("toId") or str(to_num)

    decoded = packet.get("decoded", {}) or {}

    # Prefer top-level channel fields (some firmwares put channel at $)
    chan = (
        packet.get("channel")
        or packet.get("channelIndex")
        or decoded.get("channel")
        or decoded.get("channelIndex")
        or 0
    )

    try:
        chan = int(chan)
    except Exception:
        chan = 0

    port = decoded.get("portnum", "")
    # ... keep the rest of your save_packet logic here ...

    # ------------------ TEXT ------------------
    if port == "TEXT_MESSAGE_APP":
        msg = decoded.get("text")
        if not msg:
            p = decoded.get("payload", "")
            if isinstance(p, bytes):
                msg = p.decode("utf-8", errors="replace")
            else:
                msg = str(p)

    # ------------------ TELEMETRY ------------------
    elif port == "TELEMETRY_APP":
        tel = decoded.get("telemetry", {})
        dm = tel.get("deviceMetrics", {}) or {}
        em = tel.get("environmentMetrics", {}) or {}

        if dm:
            msg = f"[Telemetry] battery={dm.get('batteryLevel')} voltage={dm.get('voltage')}"
        elif em:
            msg = (
                f"[Env] temp={em.get('temperature')} "
                f"RH={em.get('relativeHumidity')} "
                f"pressure={em.get('barometricPressure')}"
            )
        else:
            msg = "[Telemetry]"

    # ------------------ GPS POSITION ------------------
    elif port == "POSITION_APP":
        pos = decoded.get("position", {}) or {}
        lat = pos.get("latitude")
        lon = pos.get("longitude")

        # microdegree fallback if needed
        if lat is None and isinstance(pos.get("latitudeI"), (int, float)):
            lat = pos["latitudeI"] / 1e7
        if lon is None and isinstance(pos.get("longitudeI"), (int, float)):
            lon = pos["longitudeI"] / 1e7

        if lat is not None and lon is not None:
            msg = f"[GPS] lat={lat}, lon={lon}"
        else:
            msg = "[GPS]"

    # ------------------ OTHER ------------------
    else:
        msg = f"[{port}]"

    # Radio metrics for flavor
    hops = packet.get("hopLimit")
    rssi = packet.get("rxRssi")
    snr = packet.get("rxSnr")

    metrics = []
    if hops is not None:
        metrics.append(f"hops={hops}")
    if rssi is not None:
        metrics.append(f"rssi={rssi}")
    if snr is not None:
        metrics.append(f"snr={snr}")

    if metrics:
        msg += " (" + ", ".join(metrics) + ")"

    label = from_id

    cur.execute(
        """
        INSERT INTO packets (timestamp, from_label, to_id, message, raw_json, channel)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            ts,
            label,
            to_id,
            msg,
            json.dumps(sanitize_for_json(packet)),
            chan,
        ),
    )

    conn.commit()
    conn.close()


#  ===========================================================
#  PACKET CALLBACK
# ===========================================================
def on_packet(packet=None, interface=None):
    """
    PubSub callback used by Meshtastic 2.6.0.
    `packet` is already a Python dict.
    """
    global last_config

    try:
        safe_packet = sanitize_for_json(packet)
        print("\n=== PACKET RECEIVED ===")
        print(json.dumps(safe_packet, indent=2))

        decoded = packet.get("decoded", {}) or {}

        # ---------- sniff for config/channels to maybe use later ----------
        if decoded.get("portnum") == "CONFIG_APP":
            cfg = decoded.get("config")
            if cfg:
                last_config = sanitize_for_json(cfg)
                print("=== RECEIVED CONFIG_APP ===")
                print(json.dumps(last_config, indent=2))

        nodeinfo = decoded.get("nodeInfo")
        if nodeinfo and isinstance(nodeinfo, dict) and "config" in nodeinfo:
            last_config = sanitize_for_json(nodeinfo["config"])
            print("=== RECEIVED CONFIG (nodeInfo) ===")
            print(json.dumps(last_config, indent=2))

        user = decoded.get("user")
        if user and isinstance(user, dict) and "config" in user:
            last_config = sanitize_for_json(user["config"])
            print("=== RECEIVED CONFIG (user.config) ===")
            print(json.dumps(last_config, indent=2))

        system = decoded.get("system")
        if system and isinstance(system, dict) and "channels" in system:
            last_config = sanitize_for_json(system)
            print("=== RECEIVED CONFIG (system.channels) ===")
            print(json.dumps(last_config, indent=2))

        # ---------- normal handling ----------
        save_packet(packet)

        # Push "packet" event for dashboard SSE
        sse_queue.put(
            {
                "type": "packet",
                "packet": safe_packet,
            }
        )

        # Push "gps-update" for map breadcrumbs
        if decoded.get("portnum") == "POSITION_APP":
            pos = decoded.get("position", {}) or {}
            lat = pos.get("latitude")
            lon = pos.get("longitude")

            if lat is None and isinstance(pos.get("latitudeI"), (int, float)):
                lat = pos["latitudeI"] / 1e7
            if lon is None and isinstance(pos.get("longitudeI"), (int, float)):
                lon = pos["longitudeI"] / 1e7

            if lat is not None and lon is not None:
                sse_queue.put(
                    {
                        "type": "gps-update",
                        "node": packet.get("fromId") or packet.get("from"),
                        "lat": lat,
                        "lon": lon,
                        "snr": packet.get("rxSnr"),
                        "rssi": packet.get("rxRssi"),
                        "hops": packet.get("hopLimit"),
                    }
                )

    except Exception as e:
        print("Packet save error:", e)


# ===========================================================
#  API: MESSAGES
# ===========================================================
@app.route("/api/messages")
def api_messages():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT timestamp, from_label, message, channel
        FROM packets
        ORDER BY id DESC
        LIMIT 200
        """
    ).fetchall()
    conn.close()

    return jsonify(
        [
            {
                "timestamp": r[0],
                "from": r[1],
                "message": r[2],
                "channel": r[3],
            }
            for r in rows
        ]
    )


# ===========================================================
#  API: SEND TEXT MESSAGE
# ===========================================================
@app.route("/api/send", methods=["POST"])
def api_send():
    try:
        data = request.get_json(force=True, silent=True) or {}
        text = data.get("text")
        dest = data.get("to")          # numeric node ID or ""
        chan = data.get("channel", 0)  # channel index (0-7 typically)

        if not text:
            return jsonify({"status": "error", "error": "Missing text"}), 400

        try:
            chan = int(chan)
        except Exception:
            chan = 0

        if dest:
            interface.sendText(text, destinationId=int(dest), channelIndex=chan)
        else:
            interface.sendText(text, channelIndex=chan)

        return jsonify({"status": "sent", "channel": chan})

    except Exception as e:
        print("Send error:", e)
        return jsonify({"status": "error", "error": str(e)}), 500


# ===========================================================
#  API: NODES
# ===========================================================
@app.route("/api/nodes")
def api_nodes():
    try:
        return jsonify(sanitize_for_json(interface.nodes))
    except Exception:
        return jsonify([])


# ===========================================================
#  API: LIVE POSITIONS FOR MAP
# ===========================================================
@app.route("/api/positions")
def api_positions():
    out = []
    try:
        nodes = interface.nodes or {}
    except Exception:
        return jsonify([])

    for key, node in nodes.items():
        user = node.get("user", {}) or {}
        pos = node.get("position", {}) or {}

        lat = pos.get("latitude")
        lon = pos.get("longitude")

        # microdegree fallback
        if lat is None and isinstance(pos.get("latitudeI"), (int, float)):
            lat = pos["latitudeI"] / 1e7
        if lon is None and isinstance(pos.get("longitudeI"), (int, float)):
            lon = pos["longitudeI"] / 1e7

        if lat is None or lon is None:
            continue

        out.append(
            {
                "nodeKey": key,
                "num": node.get("num"),  # numeric node ID
                "lat": lat,
                "lon": lon,
                "time": node.get("lastHeard"),

                "shortName": user.get("shortName"),
                "longName": user.get("longName"),
                "radioId": user.get("id"),

                "snr": node.get("snr"),
                "rssi": node.get("rssi"),
                "hops": node.get("hops"),
                "lastHeard": node.get("lastHeard"),
            }
        )

    return jsonify(out)


# ===========================================================
#  API: TERMINATOR BUTTON
# ===========================================================
@app.route("/api/command/terminator", methods=["POST"])
def api_terminator():
    data = request.get_json(force=True, silent=True) or {}
    chan = data.get("channel", 0)

    try:
        chan = int(chan)
    except Exception:
        chan = 0

    # 1) Decide WHAT position to send
    # Option: use your own node's current position if available.
    # Replace YOUR_NODE_NUM with the gateway's node num if you know it,
    # or pick the most recently heard node with position.
    lat = lon = None

    try:
        # Example: pick first node that has position
        nodes = interface.nodes or {}
        for _, n in nodes.items():
            pos = (n.get("position") or {})
            lat = pos.get("latitude")
            lon = pos.get("longitude")
            if lat is None and isinstance(pos.get("latitudeI"), (int, float)):
                lat = pos["latitudeI"] / 1e7
            if lon is None and isinstance(pos.get("longitudeI"), (int, float)):
                lon = pos["longitudeI"] / 1e7
            if lat is not None and lon is not None:
                break
    except Exception:
        pass

    # 2) Send a TRUE position packet if we have coordinates
    sent_pos = False
    if lat is not None and lon is not None:
        try:
            # Depending on meshtastic-python version, sendPosition may or may not accept channelIndex.
            # Try with channelIndex first; fallback to without it.
            try:
                interface.sendPosition(latitude=lat, longitude=lon, channelIndex=chan)
            except TypeError:
                interface.sendPosition(latitude=lat, longitude=lon)
            sent_pos = True
        except Exception as e:
            print("terminator sendPosition error:", e)

    # 3) Send a status TEXT on the selected channel
    try:
        interface.sendText("🚨 GPS Positioning status broadcast", channelIndex=chan)
    except Exception as e:
        print("terminator sendText error:", e)
        return jsonify({"status": "error", "error": str(e), "channel": chan}), 500

    return jsonify({
        "status": "sent",
        "channel": chan,
        "sent_position": sent_pos,
        "lat": lat,
        "lon": lon
    })



# ===========================================================
#  API: POSITION HISTORY (for breadcrumb replay)
# ===========================================================
@app.route("/api/position_history")
def api_position_history():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    rows = cur.execute(
        """
        SELECT timestamp, from_label, raw_json
        FROM packets
        WHERE message LIKE '[GPS]%'
        ORDER BY id DESC
        LIMIT 500
        """
    ).fetchall()

    out = []

    for ts, label, raw in rows:
        try:
            pkt = json.loads(raw)
            pos = (pkt.get("decoded") or {}).get("position", {}) or {}
            lat = pos.get("latitude")
            lon = pos.get("longitude")

            if lat is None and isinstance(pos.get("latitudeI"), (int, float)):
                lat = pos["latitudeI"] / 1e7
            if lon is None and isinstance(pos.get("longitudeI"), (int, float)):
                lon = pos["longitudeI"] / 1e7

            if lat is not None and lon is not None:
                out.append(
                    {
                        "time": ts,
                        "node": pkt.get("fromId") or pkt.get("from"),
                        "lat": lat,
                        "lon": lon,
                    }
                )
        except Exception:
            pass

    conn.close()
    return jsonify(out)


# ===========================================================
#  API: CHANNELS
# ===========================================================
@app.route("/api/channels")
def api_channels():
    # For now this just returns static CHANNELS.
    # Later we can parse last_config to override.
    return jsonify(CHANNELS)


# ===========================================================
#  STATIC PAGES
# ===========================================================
@app.route("/map")
def map_page():
    return send_from_directory("static", "map.html")


@app.route("/")
def index():
    return send_from_directory("static", "dashboard.html")


# ===========================================================
#  SERVER-SENT EVENTS
# ===========================================================
@app.route("/events")
def sse_events():
    def generate():
        while True:
            try:
                event = sse_queue.get(block=True)
                safe = sanitize_for_json(event)
                line = "data: " + json.dumps(safe) + "\n\n"
                # WSGI/werkzeug requires bytes
                yield line.encode("utf-8")
            except Exception as e:
                print("SSE stream error:", e)
                time.sleep(0.1)

    return Response(generate(), mimetype="text/event-stream")


# ===========================================================
#  DEBUG ROUTE (fake packet)
# ===========================================================
@app.route("/debug_packet")
def debug_packet():
    on_packet({"from": 123, "decoded": {"text": "TEST PACKET"}}, None)
    return "ok"



# ===========================================================
#  MAIN
# ===========================================================
if __name__ == "__main__":
    print("Initializing database...")
    init_db()

    print(f"Connecting to Meshtastic on {SERIAL_PORT}...")
    interface = meshtastic.serial_interface.SerialInterface(SERIAL_PORT)

    print("Subscribing to packet events...")
    topics = [
        "meshtastic.receive",
        "meshtastic.packet",
        "meshtastic.nodeinfo",
        "meshtastic.nodeInfo",
        "meshtastic.position",
        "meshtastic.telemetry",
        "meshtastic.raw",
        "meshtastic.radio",
    ]

    for t in topics:
        try:
            pub.subscribe(on_packet, t)
            print("Subscribed to:", t)
        except Exception as e:
            print("Failed to subscribe to:", t, e)

    print("Starting web server on http://0.0.0.0:5000 ...")
    app.run("0.0.0.0", 5000)
