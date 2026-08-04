import { useState, type FormEvent } from "react";
import argusLogo from "../assets/argus_logo.png";
import { login, register } from "../lib/api";
import type { AuthUser } from "../lib/auth";

interface LoginPageProps {
  onAuthed: (user: AuthUser) => void;
}

export function LoginPage({ onAuthed }: LoginPageProps) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const res = mode === "login" ? await login(username, password) : await register(username, password);
      onAuthed(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(circle_at_20%_20%,#132033,transparent_40%),radial-gradient(circle_at_80%_0%,#1a2b22,transparent_35%),#0b1220] px-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md space-y-5 rounded-2xl border border-white/10 bg-black/30 p-8 shadow-2xl backdrop-blur"
      >
        <div className="flex flex-col items-center gap-3 text-center">
          <img src={argusLogo} alt="ARGUS" className="h-14 w-auto" />
          <h1 className="text-xl font-semibold tracking-wide text-white">
            {mode === "login" ? "Sign in" : "Create account"}
          </h1>
          <p className="text-sm text-slate-400">Each account gets an isolated ARGUS workspace.</p>
        </div>

        <label className="block space-y-1 text-sm text-slate-300">
          <span>Username</span>
          <input
            className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-white outline-none focus:border-cyan-400"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            minLength={3}
            required
          />
        </label>

        <label className="block space-y-1 text-sm text-slate-300">
          <span>Password</span>
          <input
            type="password"
            className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-white outline-none focus:border-cyan-400"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            minLength={6}
            required
          />
        </label>

        {error ? <p className="text-sm text-rose-300">{error}</p> : null}

        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-lg bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:opacity-60"
        >
          {busy ? "Please wait…" : mode === "login" ? "Sign in" : "Register"}
        </button>

        <button
          type="button"
          className="w-full text-sm text-slate-400 underline-offset-2 hover:text-white hover:underline"
          onClick={() => {
            setMode(mode === "login" ? "register" : "login");
            setError("");
          }}
        >
          {mode === "login" ? "Need an account? Register" : "Already have an account? Sign in"}
        </button>
      </form>
    </div>
  );
}
