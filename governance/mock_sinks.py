"""
Self-contained mock SIEM receivers for local verification and automated testing:
- Mock HTTP Collector (accepts Splunk HEC, Elastic ECS, Webhooks, Datadog, Sentinel, CloudWatch)
- Mock Syslog TCP Server (accepts CEF / RFC 5424 formatted lines)
"""

from __future__ import annotations

import json
import logging
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Dict, List, Optional

logger = logging.getLogger("g1.governance.mock_sinks")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class MockHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default server access logs

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            payload = {"raw": body.decode("utf-8", errors="replace")}

        event_entry = {
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "payload": payload,
        }

        # Thread-safe append to server's received list
        if hasattr(self.server, "received_events"):
            self.server.received_events.append(event_entry)

        # Standard successful response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"success","acknowledged":true}')


class MockHTTPSink:
    """Mock HTTP receiver capturing POST payloads."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.server = ThreadedHTTPServer((host, port), MockHTTPHandler)
        self.server.received_events: List[Dict[str, Any]] = []
        self.host, self.port = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def get_events(self) -> List[Dict[str, Any]]:
        return list(self.server.received_events)

    def clear(self) -> None:
        self.server.received_events.clear()

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


class MockSyslogTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(8192)
        if data and hasattr(self.server, "received_lines"):
            self.server.received_lines.append(data.decode("utf-8", errors="replace"))


class MockSyslogSink:
    """Mock TCP Syslog sink capturing raw CEF messages."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.server = socketserver.TCPServer((host, port), MockSyslogTCPHandler)
        self.server.received_lines: List[str] = []
        self.host, self.port = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def get_lines(self) -> List[str]:
        return list(self.server.received_lines)

    def clear(self) -> None:
        self.server.received_lines.clear()


class MockReceiverCluster:
    """Manages the full suite of local mock SIEM listeners for demo and testing."""

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.http_ports = [18088, 19200, 14318, 18090, 18091, 18092]
        self.syslog_port = 15514
        self.http_sinks: Dict[int, MockHTTPSink] = {}
        self.syslog_sink: Optional[MockSyslogSink] = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> Dict[str, Any]:
        with self._lock:
            if self._running:
                return self.get_status()
            started_ports = []
            for p in self.http_ports:
                try:
                    sink = MockHTTPSink(host=self.host, port=p)
                    sink.start()
                    self.http_sinks[p] = sink
                    started_ports.append(p)
                except Exception as e:
                    logger.warning(f"Could not bind mock HTTP port {p}: {e}")

            try:
                self.syslog_sink = MockSyslogSink(host=self.host, port=self.syslog_port)
                self.syslog_sink.start()
                started_ports.append(self.syslog_port)
            except Exception as e:
                logger.warning(f"Could not bind mock Syslog port {self.syslog_port}: {e}")

            self._running = True
            return {"running": True, "active_ports": started_ports}

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self._running:
                return {"running": False, "active_ports": []}
            for p, sink in list(self.http_sinks.items()):
                try:
                    sink.stop()
                except Exception:
                    pass
            self.http_sinks.clear()
            if self.syslog_sink:
                try:
                    self.syslog_sink.stop()
                except Exception:
                    pass
                self.syslog_sink = None
            self._running = False
            return {"running": False, "active_ports": []}

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            ports = list(self.http_sinks.keys())
            if self.syslog_sink:
                ports.append(self.syslog_port)
            return {"running": self._running, "active_ports": ports}

