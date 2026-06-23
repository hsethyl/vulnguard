"""Tkinter GUI for vulnguard - a one-click, double-click-to-run interface.

Designed to be packaged into a single portable .exe (PyInstaller) so it runs
from a USB stick with no Python install. tkinter ships with CPython, so the
GUI needs no third-party dependencies.

Threading note: tkinter is not thread-safe, so scans run on a worker thread
and results are marshalled back to the UI thread via root.after(...).
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from . import __version__
from .dast.client import DastError, scan_url
from .engine import scan_paths
from .fixers.engine import apply_fixes
from .models import ScanResult, Severity
from .report.json_report import render_json

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#b00020",
    Severity.HIGH: "#d32f2f",
    Severity.MEDIUM: "#ed6c02",
    Severity.LOW: "#0277bd",
}


class VulnGuardApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.last_result: ScanResult | None = None
        self.target_path = tk.StringVar()
        self.use_osv = tk.BooleanVar(value=False)
        self.dast_url = tk.StringVar()
        self.dast_authorized = tk.BooleanVar(value=False)

        root.title(f"VulnGuard {__version__} - 취약점 검사 / 자동 보완")
        root.geometry("960x640")
        root.minsize(720, 480)

        self._build_target_row()
        self._build_action_row()
        self._build_dast_row()
        self._build_output()
        self._build_status()
        self._log_intro()

    # --- UI construction -------------------------------------------------

    def _build_target_row(self) -> None:
        frame = ttk.LabelFrame(self.root, text="1) 검사할 폴더/파일")
        frame.pack(fill="x", padx=10, pady=(10, 4))
        entry = ttk.Entry(frame, textvariable=self.target_path)
        entry.pack(side="left", fill="x", expand=True, padx=(8, 4), pady=8)
        ttk.Button(frame, text="폴더 선택", command=self._choose_dir).pack(side="left", padx=2, pady=8)
        ttk.Button(frame, text="파일 선택", command=self._choose_file).pack(side="left", padx=2, pady=8)
        ttk.Checkbutton(
            frame, text="온라인 의존성 검사(OSV, 인터넷 필요)", variable=self.use_osv
        ).pack(side="left", padx=8, pady=8)

    def _build_action_row(self) -> None:
        frame = ttk.LabelFrame(self.root, text="2) 실행")
        frame.pack(fill="x", padx=10, pady=4)
        self.btn_scan = ttk.Button(frame, text="🔍 검사 시작", command=self._run_scan)
        self.btn_scan.pack(side="left", padx=6, pady=8)
        self.btn_preview = ttk.Button(frame, text="🛠 자동수정 미리보기", command=self._run_fix_preview)
        self.btn_preview.pack(side="left", padx=6, pady=8)
        self.btn_apply = ttk.Button(frame, text="✅ 수정 적용(백업됨)", command=self._run_fix_apply)
        self.btn_apply.pack(side="left", padx=6, pady=8)
        self.btn_save = ttk.Button(frame, text="💾 결과 저장(JSON)", command=self._save_report)
        self.btn_save.pack(side="left", padx=6, pady=8)

    def _build_dast_row(self) -> None:
        frame = ttk.LabelFrame(self.root, text="(선택) 실행 중인 웹사이트 점검 - 수동/passive")
        frame.pack(fill="x", padx=10, pady=4)
        ttk.Label(frame, text="URL:").pack(side="left", padx=(8, 2), pady=8)
        ttk.Entry(frame, textvariable=self.dast_url).pack(side="left", fill="x", expand=True, padx=2, pady=8)
        ttk.Checkbutton(
            frame, text="권한 있음(외부 사이트)", variable=self.dast_authorized
        ).pack(side="left", padx=4, pady=8)
        ttk.Button(frame, text="🌐 웹 점검", command=self._run_dast).pack(side="left", padx=6, pady=8)

    def _build_output(self) -> None:
        self.output = scrolledtext.ScrolledText(self.root, wrap="word", font=("Consolas", 10))
        self.output.pack(fill="both", expand=True, padx=10, pady=4)
        for severity, color in _SEVERITY_COLOR.items():
            self.output.tag_config(severity.label, foreground=color)
        self.output.tag_config("HEAD", font=("Consolas", 11, "bold"))
        self.output.tag_config("DIM", foreground="#777777")
        self.output.tag_config("OK", foreground="#2e7d32", font=("Consolas", 11, "bold"))
        self.output.configure(state="disabled")

    def _build_status(self) -> None:
        self.status = tk.StringVar(value="준비됨")
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", side="bottom")
        ttk.Label(bar, textvariable=self.status, anchor="w").pack(side="left", fill="x", expand=True, padx=10, pady=4)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self.progress.pack(side="right", padx=10, pady=4)

    # --- helpers ---------------------------------------------------------

    def _log_intro(self) -> None:
        self._write("VulnGuard - 코드 취약점 검사 및 자동 보완 도구\n", "HEAD")
        self._write(
            "사용법: ① 위에서 폴더를 선택하고 ② '검사 시작'을 누르세요.\n"
            "수정 가능한 항목은 '자동수정 미리보기'로 확인 후 '수정 적용'을 누르면 됩니다.\n"
            "본인이 소유하거나 허가받은 코드/시스템에만 사용하세요.\n\n",
            "DIM",
        )

    def _write(self, text: str, tag: str | None = None) -> None:
        self.output.configure(state="normal")
        if tag:
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _clear(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    def _choose_dir(self) -> None:
        path = filedialog.askdirectory(title="검사할 폴더 선택")
        if path:
            self.target_path.set(path)

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename(title="검사할 파일 선택")
        if path:
            self.target_path.set(path)

    def _set_busy(self, busy: bool, message: str) -> None:
        self.status.set(message)
        state = "disabled" if busy else "normal"
        for btn in (self.btn_scan, self.btn_preview, self.btn_apply, self.btn_save):
            btn.configure(state=state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _require_target(self) -> str | None:
        path = self.target_path.get().strip()
        if not path:
            messagebox.showwarning("폴더 필요", "먼저 검사할 폴더나 파일을 선택하세요.")
            return None
        return path

    def _run_in_thread(self, work, done) -> None:
        def runner():
            try:
                result = work()
                self.root.after(0, lambda: done(result, None))
            except Exception as exc:  # surface any error in the UI thread
                self.root.after(0, lambda: done(None, exc))

        threading.Thread(target=runner, daemon=True).start()

    # --- actions ---------------------------------------------------------

    def _run_scan(self) -> None:
        path = self._require_target()
        if not path:
            return
        self._clear()
        self._set_busy(True, "검사 중...")
        osv = self.use_osv.get()
        self._run_in_thread(lambda: scan_paths([path], osv=osv), self._scan_done)

    def _scan_done(self, result: ScanResult | None, error: Exception | None) -> None:
        self._set_busy(False, "준비됨")
        if error:
            messagebox.showerror("검사 오류", str(error))
            return
        self.last_result = result
        self._render_result(result)

    def _render_result(self, result: ScanResult) -> None:
        counts = result.counts_by_severity()
        self._write(f"검사한 파일: {result.scanned_files}개\n", "DIM")
        if not result.has_findings:
            self._write("\n취약점이 발견되지 않았습니다. ✔\n", "OK")
        else:
            self._write(f"발견된 취약점: {len(result.findings)}개\n\n", "HEAD")
            for f in result.sorted_findings():
                loc = f.file_path + (f":{f.line}" if f.line else "")
                cwe = f" [{f.cwe}]" if f.cwe else ""
                fixable = "  (자동수정 가능)" if f.fixable else ""
                self._write(f"[{f.severity.label}] ", f.severity.label)
                self._write(f"{f.rule_id}{cwe}  {loc}{fixable}\n", "HEAD")
                self._write(f"    {f.message}\n")
                if f.snippet:
                    self._write(f"    > {f.snippet}\n", "DIM")
                if f.remediation:
                    self._write(f"    해결: {f.remediation}\n", "DIM")
                self._write("\n")
        summary = "  ".join(f"{s.label}: {counts[s.label]}" for s in sorted(Severity, reverse=True))
        self._write("요약  " + summary + "\n", "HEAD")
        fixable_n = sum(1 for f in result.findings if f.fixable)
        if fixable_n:
            self._write(f"\n자동수정 가능한 항목이 {fixable_n}개 있습니다. '자동수정 미리보기'를 눌러보세요.\n", "OK")
        self.status.set(f"완료 - 취약점 {len(result.findings)}개")

    def _run_fix_preview(self) -> None:
        path = self._require_target()
        if not path:
            return
        self._set_busy(True, "수정 미리보기 계산 중...")

        def work():
            result = scan_paths([path])
            report = apply_fixes(list(result.findings), path, apply=False)
            return report

        self._run_in_thread(work, lambda r, e: self._fix_done(r, e, applied=False))

    def _run_fix_apply(self) -> None:
        path = self._require_target()
        if not path:
            return
        if not messagebox.askyesno(
            "수정 적용",
            "선택한 코드 파일을 안전한 코드로 수정합니다.\n"
            "원본은 *.vulnguard.bak 으로 백업됩니다.\n\n계속할까요?",
        ):
            return
        self._set_busy(True, "수정 적용 중...")

        def work():
            result = scan_paths([path])
            report = apply_fixes(list(result.findings), path, apply=True)
            return report

        self._run_in_thread(work, lambda r, e: self._fix_done(r, e, applied=True))

    def _fix_done(self, report, error, applied: bool) -> None:
        self._set_busy(False, "준비됨")
        if error:
            messagebox.showerror("수정 오류", str(error))
            return
        self._clear()
        if not report.file_fixes:
            self._write("자동으로 수정할 수 있는 항목이 없습니다.\n", "DIM")
            self._write("(eval, SQL 인젝션 등은 코드 의미를 바꿀 수 있어 수동 수정이 필요합니다.)\n", "DIM")
            return
        title = "수정 적용 결과" if applied else "수정 미리보기 (아직 파일은 바뀌지 않음)"
        self._write(title + "\n\n", "HEAD")
        for fix in report.file_fixes:
            self._write(f"=== {fix.file_path}  ({fix.change_count}곳) ===\n", "HEAD")
            self._write((fix.diff or "(변경 미리보기 없음)") + "\n\n")
        if report.env_vars:
            self._write("환경변수로 옮길 시크릿(.env.example 에 기록):\n", "HEAD")
            for name, _ in report.env_vars:
                self._write(f"  {name}\n")
            self._write("\n")
        if applied:
            self._write(f"총 {report.total_changes}곳 수정 완료. 백업: *.vulnguard.bak\n", "OK")
            self._write("주의: 노출된 비밀키는 반드시 재발급(rotate)하세요.\n", "MEDIUM" if False else "DIM")
            messagebox.showinfo("완료", f"{report.total_changes}곳을 수정했습니다. 원본은 백업되었습니다.")
        else:
            self._write(f"적용하면 총 {report.total_changes}곳이 바뀝니다. '수정 적용'을 누르세요.\n", "OK")

    def _run_dast(self) -> None:
        url = self.dast_url.get().strip()
        if not url:
            messagebox.showwarning("URL 필요", "점검할 웹사이트 URL을 입력하세요.")
            return
        self._clear()
        self._set_busy(True, "웹 점검 중...")
        authorized = self.dast_authorized.get()

        def work():
            return scan_url(url, authorized=authorized)

        def done(result, error):
            self._set_busy(False, "준비됨")
            if isinstance(error, DastError):
                messagebox.showwarning("점검 불가", str(error))
                return
            if error:
                messagebox.showerror("오류", str(error))
                return
            self.last_result = result
            self._write(f"웹 점검 결과: {url}\n\n", "HEAD")
            self._render_result(result)

        self._run_in_thread(work, done)

    def _save_report(self) -> None:
        if not self.last_result:
            messagebox.showinfo("저장할 결과 없음", "먼저 검사를 실행하세요.")
            return
        path = filedialog.asksaveasfilename(
            title="결과 저장", defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("모든 파일", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(render_json(self.last_result))
        except OSError as exc:
            messagebox.showerror("저장 오류", str(exc))
            return
        messagebox.showinfo("저장됨", f"결과를 저장했습니다:\n{path}")


def main() -> int:
    import sys

    if "--selftest" in sys.argv:
        # Headless construction check: build the window, then close it.
        root = tk.Tk()
        VulnGuardApp(root)
        root.withdraw()
        root.after(200, root.destroy)
        root.mainloop()
        print("GUI selftest OK")
        return 0

    root = tk.Tk()
    VulnGuardApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
