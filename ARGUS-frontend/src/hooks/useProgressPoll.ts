import { useEffect } from "react";

export function useProgressPoll<T>(
  enabled: boolean,
  fetchFn: () => Promise<T>,
  onUpdate: (value: T) => void,
  intervalMs = 1500,
) {
  useEffect(() => {
    if (!enabled) return;
    void fetchFn().then(onUpdate).catch(() => {});
    const poll = window.setInterval(() => {
      void fetchFn().then(onUpdate).catch(() => {});
    }, intervalMs);
    return () => window.clearInterval(poll);
  }, [enabled, fetchFn, onUpdate, intervalMs]);
}
