import { useEffect, useRef, useState } from "react";
import type { SecurityEvent } from "./types";

type Status = "connecting" | "open" | "closed";

interface Live {
  events: SecurityEvent[];
  status: Status;
  clear: () => void;
}

// Subscribes to the admin WebSocket feed. Reconnects with backoff. The server authorises the
// socket via the admin session cookie; no token is ever sent in a frame.
export function useLiveEvents(enabled: boolean, cap = 300): Live {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [status, setStatus] = useState<Status>("closed");
  const wsRef = useRef<WebSocket | null>(null);
  const retry = useRef(0);
  const alive = useRef(true);

  useEffect(() => {
    if (!enabled) return;
    alive.current = true;

    const connect = () => {
      if (!alive.current) return;
      setStatus("connecting");
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/ws/security-events`);
      wsRef.current = ws;

      ws.onopen = () => {
        retry.current = 0;
        setStatus("open");
      };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "event") {
            const e = msg.data as SecurityEvent;
            // De-duplicate by event id: the server replays recent events on connect, and React
            // StrictMode mounts the socket twice in dev, so the same id can arrive more than once.
            setEvents((prev) => (prev.some((p) => p.id === e.id) ? prev : [e, ...prev].slice(0, cap)));
          }
        } catch {
          /* ignore malformed frame */
        }
      };
      ws.onclose = () => {
        setStatus("closed");
        if (!alive.current) return;
        retry.current = Math.min(retry.current + 1, 6);
        setTimeout(connect, 500 * 2 ** retry.current);
      };
      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      alive.current = false;
      wsRef.current?.close();
    };
  }, [enabled, cap]);

  return { events, status, clear: () => setEvents([]) };
}
