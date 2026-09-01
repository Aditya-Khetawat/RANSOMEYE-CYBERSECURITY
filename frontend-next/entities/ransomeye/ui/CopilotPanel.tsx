"use client";

import { useEffect, useRef, useState } from "react";
import { Button, Card, Text, Textarea, Title } from "@tremor/react";
import { HiOutlineSparkles } from "react-icons/hi2";
import { LuSend } from "react-icons/lu";
import { MarkdownHTML } from "@/shared/ui/MarkdownHTML/MarkdownHTML";
import type { CopilotMessage } from "../model/types";
import { useRansomEyeCopilot } from "../model/useRansomEye";

const SUGGESTIONS = [
  "Why was this endpoint flagged?",
  "What behaviors were observed?",
  "What happens next if unaddressed?",
  "What should I do right now?",
];

/** Inline analyst copilot, scoped to whichever endpoint is selected. Reuses
 * the alert correlation engine's LLM plumbing under the hood (see backend
 * copilot.py / assistant_bridge.py) — never the detector itself, only the
 * narrator. */
export function CopilotPanel({ endpointId }: { endpointId: string }) {
  const { ask, isAsking } = useRansomEyeCopilot();
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setMessages([]);
    setError(null);
  }, [endpointId]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isAsking]);

  const send = async (question: string) => {
    const q = question.trim();
    if (!q || isAsking) return;
    setError(null);
    const conversation = messages;
    setMessages((m) => [...m, { role: "user", content: q }]);
    setInput("");
    try {
      const res = await ask(endpointId, q, conversation);
      setMessages((m) => [...m, { role: "assistant", content: res.answer }]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Card className="p-4 flex flex-col gap-2 h-full">
      <div className="flex items-center gap-2">
        <HiOutlineSparkles className="w-4 h-4 text-red-500" />
        <Title className="text-sm">Analyst Copilot · {endpointId}</Title>
      </div>

      <div className="flex-1 overflow-y-auto max-h-64 flex flex-col gap-2 py-1">
        {messages.length === 0 && (
          <Text className="text-xs text-gray-500">Ask why this endpoint was flagged, or what to do next.</Text>
        )}
        {messages.map((m, i) => (
          <div
            key={i}
            className={
              m.role === "user"
                ? "self-end max-w-[85%] rounded-lg bg-red-500 text-white px-3 py-1.5 text-xs"
                : "self-start max-w-[95%] rounded-lg bg-gray-100 px-3 py-1.5 text-xs"
            }
          >
            {m.role === "user" ? m.content : <MarkdownHTML>{m.content}</MarkdownHTML>}
          </div>
        ))}
        {error && <div className="text-xs text-red-600">{error}</div>}
        <div ref={endRef} />
      </div>

      {messages.length === 0 && (
        <div className="flex flex-wrap gap-1">
          {SUGGESTIONS.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => send(s)}
              className="text-[11px] rounded-full border border-gray-200 px-2 py-0.5 hover:border-red-400 hover:text-red-600"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      <div className="flex items-end gap-2 border-t border-gray-200 pt-2">
        <Textarea
          rows={1}
          autoHeight
          className="flex-1 resize-none max-h-24"
          placeholder="Ask the copilot..."
          value={input}
          onValueChange={setInput}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send(input);
            }
          }}
        />
        <Button size="xs" color="red" icon={LuSend} loading={isAsking} disabled={!input.trim()} onClick={() => send(input)}>
          Send
        </Button>
      </div>
    </Card>
  );
}
