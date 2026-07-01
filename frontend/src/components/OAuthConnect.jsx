import { useCallback, useEffect, useRef, useState } from "react";
import {
  SignIn,
  ArrowSquareOut,
  CircleNotch,
  CheckCircle,
  Warning,
  Copy,
} from "@phosphor-icons/react";

import { oauthStart, oauthPoll, oauthComplete } from "../lib/api";

const inputCls =
  "w-full bg-zinc-900/60 border border-white/[0.08] px-3 py-2 text-[13px] text-zinc-100 " +
  "placeholder:text-zinc-600 focus:border-emerald-500/50 outline-none transition-colors";

/**
 * Sign-in panel for an OAuth provider. Runs the device-code or browser-PKCE flow entirely
 * against SecForge's own backend (/oauth/*), which stores the resulting token as a normal
 * account. Its own component so the API-key form in ConnectModal stays simple.
 *
 * @param {{
 *   provider: { id: string, label: string, flow?: string, risk?: boolean },
 *   t: Record<string, any>,
 *   onConnected: () => void,
 * }} props
 */
export default function OAuthConnect({ provider, t, onConnected }) {
  const [label, setLabel] = useState("");
  const [session, setSession] = useState(null); // { session_id, flow, user_code, verification_uri, authorize_url, interval }
  const [phase, setPhase] = useState("idle"); // idle | starting | waiting | done | error
  const [err, setErr] = useState("");
  const [code, setCode] = useState("");
  const pollRef = useRef(null);

  // Stop polling on unmount or when the provider changes.
  const stopPoll = useCallback(() => {
    if (pollRef.current) {
      clearTimeout(pollRef.current);
      pollRef.current = null;
    }
  }, []);
  useEffect(() => stopPoll, [stopPoll]);
  useEffect(() => {
    stopPoll();
    setSession(null);
    setPhase("idle");
    setErr("");
    setCode("");
    setLabel("");
  }, [provider, stopPoll]);

  const pollOnce = useCallback(
    (sid, interval) => {
      pollRef.current = setTimeout(async () => {
        try {
          const r = await oauthPoll(sid, label);
          if (r.status === "done") {
            setPhase("done");
            onConnected();
          } else {
            pollOnce(sid, r.interval || interval);
          }
        } catch (e) {
          setErr(String(e.message || e));
          setPhase("error");
        }
      }, Math.max(1, interval) * 1000);
    },
    [label, onConnected]
  );

  const onStart = useCallback(async () => {
    setPhase("starting");
    setErr("");
    try {
      const s = await oauthStart(provider.id);
      setSession(s);
      if (s.flow === "device") {
        setPhase("waiting");
        pollOnce(s.session_id, s.interval || 5);
      } else {
        setPhase("waiting"); // pkce: wait for the user to paste the code
      }
    } catch (e) {
      setErr(String(e.message || e));
      setPhase("error");
    }
  }, [provider.id, pollOnce]);

  const onComplete = useCallback(async () => {
    if (!session || !code.trim()) return;
    setPhase("starting");
    try {
      await oauthComplete(session.session_id, code.trim(), label);
      setPhase("done");
      onConnected();
    } catch (e) {
      setErr(String(e.message || e));
      setPhase("error");
    }
  }, [session, code, label, onConnected]);

  if (phase === "done") {
    return (
      <div className="flex items-center gap-2 text-[13px] text-emerald-400 py-2">
        <CheckCircle size={16} weight="fill" /> {t.oauthDone}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {provider.risk && (
        <p className="flex items-start gap-2 text-[11.5px] leading-relaxed text-amber-300/90 border border-amber-500/25 bg-amber-500/[0.06] px-3 py-2">
          <Warning size={15} weight="fill" className="mt-0.5 shrink-0" /> {t.oauthRisk}
        </p>
      )}

      <label className="block">
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 mb-1 block">
          {t.rtLabel} <span className="text-zinc-600 normal-case">· {t.pvOptional}</span>
        </span>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          className={inputCls}
          placeholder={provider.label}
          disabled={phase === "waiting"}
        />
      </label>

      {phase === "idle" && (
        <button
          onClick={onStart}
          className="flex items-center gap-2 px-4 py-2 text-[13px] font-semibold bg-emerald-500 text-zinc-950 hover:bg-emerald-400 transition-colors"
        >
          <SignIn size={15} weight="bold" /> {t.oauthSignIn}
        </button>
      )}

      {phase === "starting" && (
        <div className="flex items-center gap-2 text-[13px] text-zinc-400 py-2">
          <CircleNotch size={15} className="animate-spin" /> {t.pvTesting}
        </div>
      )}

      {/* Device flow: show the code + verification URL, poll in the background. */}
      {phase === "waiting" && session?.flow === "device" && (
        <div className="space-y-2.5 border border-white/[0.08] bg-zinc-900/40 p-3">
          <p className="text-[12px] text-zinc-400">{t.oauthDeviceStep}</p>
          <div className="flex items-center gap-2">
            <code className="text-[18px] font-mono font-bold tracking-[0.25em] text-emerald-300 bg-zinc-950 px-3 py-1.5 border border-emerald-500/25">
              {session.user_code}
            </code>
            <button
              onClick={() => navigator.clipboard?.writeText(session.user_code)}
              title={t.oauthCopy}
              className="w-8 h-8 flex items-center justify-center border border-white/[0.08] text-zinc-500 hover:text-emerald-400"
            >
              <Copy size={14} />
            </button>
          </div>
          <a
            href={session.verification_uri_complete || session.verification_uri}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 text-[13px] font-medium text-emerald-400 hover:text-emerald-300"
          >
            {t.oauthOpenPage} <ArrowSquareOut size={13} />
          </a>
          <p className="flex items-center gap-2 text-[12px] text-zinc-500 pt-1">
            <CircleNotch size={13} className="animate-spin" /> {t.oauthWaiting}
          </p>
        </div>
      )}

      {/* PKCE flow: open the authorize URL, then paste the returned code. */}
      {phase === "waiting" && session?.flow === "pkce" && (
        <div className="space-y-2.5 border border-white/[0.08] bg-zinc-900/40 p-3">
          <a
            href={session.authorize_url}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 text-[13px] font-medium text-emerald-400 hover:text-emerald-300"
          >
            {t.oauthOpenSignIn} <ArrowSquareOut size={13} />
          </a>
          <p className="text-[12px] text-zinc-500">{t.oauthPasteStep}</p>
          <div className="flex gap-2">
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className={inputCls}
              placeholder={t.oauthCodePlaceholder}
            />
            <button
              onClick={onComplete}
              disabled={!code.trim()}
              className="shrink-0 px-4 py-2 text-[13px] font-semibold bg-emerald-500 text-zinc-950 hover:bg-emerald-400 transition-colors disabled:opacity-40 disabled:bg-zinc-800 disabled:text-zinc-500"
            >
              {t.pvConnectBtn}
            </button>
          </div>
        </div>
      )}

      {err && <p className="text-[12px] text-red-400/90">{err}</p>}
      {phase === "error" && (
        <button
          onClick={onStart}
          className="text-[12px] text-zinc-400 hover:text-emerald-400 underline underline-offset-2"
        >
          {t.oauthRetry}
        </button>
      )}
    </div>
  );
}
