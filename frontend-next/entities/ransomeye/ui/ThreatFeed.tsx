"use client";

import { useMemo } from "react";
import { Badge, Card, Text, Title } from "@tremor/react";
import type { Tick, TelemetryEvent } from "../model/types";
import { eventIcon, eventSummary, formatTickTime } from "../lib/format";

type FeedItem = { epId: string; ts: string; ev: TelemetryEvent };

/** Newest-first stream of every telemetry event revealed so far, across the
 * whole fleet — this is what an EDR console's live feed actually looks
 * like: mostly quiet, with the target endpoint's row going noisy. */
export function ThreatFeed({ ticks, maxItems = 40 }: { ticks: Tick[]; maxItems?: number }) {
  const items = useMemo(() => {
    const flat: FeedItem[] = [];
    for (const tick of ticks) {
      for (const [epId, events] of Object.entries(tick.events_by_endpoint)) {
        for (const ev of events) {
          flat.push({ epId, ts: ev.ts, ev });
        }
      }
    }
    flat.reverse();
    return flat.slice(0, maxItems);
  }, [ticks, maxItems]);

  return (
    <Card className="p-4 flex flex-col gap-2 h-full">
      <div className="flex items-center justify-between">
        <Title className="text-sm">Live Threat Feed</Title>
        <Badge size="xs" color="gray">{items.length} recent events</Badge>
      </div>
      <div className="flex-1 overflow-y-auto max-h-96 flex flex-col gap-1 pr-1">
        {items.length === 0 && <Text className="text-xs text-gray-400">No telemetry yet.</Text>}
        {items.map((item, i) => {
          const ev = item.ev;
          const suspicious =
            (ev.type === "process" && ev.suspicious_indicators.length > 0) ||
            (ev.type === "network" && ev.reputation === "malicious") ||
            ev.type === "privilege" ||
            (ev.type === "file" && ev.op === "rename" && !!ev.new_ext);
          return (
            <div
              key={i}
              className={
                "text-xs flex items-start gap-2 rounded px-2 py-1 " +
                (suspicious ? "bg-red-50 text-red-800" : "text-gray-700")
              }
            >
              <span className="shrink-0">{eventIcon(ev)}</span>
              <span className="shrink-0 text-gray-400 tabular-nums">{formatTickTime(item.ts)}</span>
              <span className="shrink-0 font-medium">{item.epId}</span>
              <span className="truncate">{eventSummary(ev)}</span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
