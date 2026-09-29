import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  LoaderCircle,
  X,
} from "lucide-react";
import { api } from "./api";

export function useLoad<T>(path: string | null, refresh = 0, poll = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    setData(null);
    setError("");
    if (!path) return;
    const load = async () => {
      setLoading(true);
      try {
        const value = await api<T>(path, { signal: controller.signal });
        if (alive) {
          setData(value);
          setError("");
        }
      } catch (err) {
        if (
          alive &&
          !(err instanceof DOMException && err.name === "AbortError")
        )
          setError(String(err instanceof Error ? err.message : err));
      } finally {
        if (alive) setLoading(false);
      }
    };
    void load();
    const interval = poll
      ? window.setInterval(() => void load(), poll)
      : undefined;
    return () => {
      alive = false;
      controller.abort();
      if (interval) clearInterval(interval);
    };
  }, [path, refresh, poll]);
  return { data, error, loading };
}
export const human = (value: string) =>
  value.replaceAll("_", " ").replaceAll("-", " ");
export const date = (value: string) =>
  new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
export const size = (bytes: number) =>
  bytes < 1024
    ? `${bytes} B`
    : bytes < 1048576
      ? `${(bytes / 1024).toFixed(1)} KiB`
      : `${(bytes / 1048576).toFixed(1)} MiB`;
export function Badge({ value }: { value: string }) {
  return (
    <span className={`badge badge-${value}`}>
      <span className="dot" />
      {human(value)}
    </span>
  );
}
export function ErrorBox({ children }: { children: ReactNode }) {
  return children ? (
    <div role="alert" className="notice error">
      <AlertCircle size={18} />
      <span>{children}</span>
    </div>
  ) : null;
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <LoaderCircle className="spin" size={20} /> Loading research data…
    </div>
  );
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-mark">◎</div>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
export function Json({ value }: { value: unknown }) {
  return <pre className="code">{JSON.stringify(value, null, 2)}</pre>;
}
export function Pager({
  total,
  offset,
  setOffset,
}: {
  total: number;
  offset: number;
  setOffset: (n: number) => void;
}) {
  return (
    <div className="pager">
      <span>
        {total ? offset + 1 : 0}–{Math.min(offset + 50, total)} of {total}
      </span>
      <div>
        <button
          aria-label="Previous page"
          disabled={!offset}
          onClick={() => setOffset(Math.max(0, offset - 50))}
        >
          <ArrowLeft size={15} />
        </button>
        <button
          aria-label="Next page"
          disabled={offset + 50 >= total}
          onClick={() => setOffset(offset + 50)}
        >
          <ArrowRight size={15} />
        </button>
      </div>
    </div>
  );
}
export function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    const opener = document.activeElement;
    dialog?.showModal();
    return () => {
      dialog?.close();
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      aria-label={title}
    >
      <div className="dialog-head">
        <h2>{title}</h2>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label="Close dialog"
        >
          <X size={20} />
        </button>
      </div>
      {children}
    </dialog>
  );
}
