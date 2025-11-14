#!/usr/bin/env python3
"""Interfaz gráfica Tkinter para monitor_ports.sh y analyze_captures.py"""

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, scrolledtext, messagebox, filedialog
from typing import Optional, List


class PortMonitorGUI:
    """Interfaz gráfica para el monitor de puertos"""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Monitor de Puertos - GUI")
        self.root.geometry("900x720")

        # Variables de estado
        self.monitor_process: Optional[subprocess.Popen] = None
        self.is_monitoring = False
        self.script_dir = Path(__file__).parent.absolute()

        # Configurar UI
        self.setup_ui()

    # ============================ UI SETUP ============================
    def setup_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        self.tab_monitor = ttk.Frame(notebook)
        self.tab_analysis = ttk.Frame(notebook)
        notebook.add(self.tab_monitor, text="Monitoreo")
        notebook.add(self.tab_analysis, text="Análisis")

        self.setup_monitor_tab()
        self.setup_analysis_tab()

    def setup_monitor_tab(self):
        frm = ttk.Frame(self.tab_monitor, padding=10)
        frm.pack(fill="both", expand=True)

        # Interface selector
        row = 0
        ttk.Label(frm, text="Interfaz de red:").grid(row=row, column=0, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_entry = ttk.Entry(frm, textvariable=self.interface_var, width=20)
        self.interface_entry.grid(row=row, column=1, sticky="w", padx=5)
        ttk.Button(frm, text="Detectar…", command=self.detect_interfaces).grid(row=row, column=2, sticky="w")

        # Mode selector
        row += 1
        ttk.Label(frm, text="Modo:").grid(row=row, column=0, sticky="w", pady=(8, 0))
        self.mode_var = tk.StringVar(value="all")
        mode_combo = ttk.Combobox(frm, textvariable=self.mode_var, values=["all", "listening", "custom"], state="readonly", width=18)
        mode_combo.grid(row=row, column=1, sticky="w", padx=5, pady=(8, 0))
        mode_combo.bind("<<ComboboxSelected>>", self.on_mode_change)

        # Ports entry (for custom)
        row += 1
        ttk.Label(frm, text="Puertos (custom):").grid(row=row, column=0, sticky="w")
        self.ports_var = tk.StringVar()
        self.ports_entry = ttk.Entry(frm, textvariable=self.ports_var, width=30, state="disabled")
        self.ports_entry.grid(row=row, column=1, sticky="w", padx=5)
        ttk.Label(frm, text="Ej: 80,443,22 o 1000-2000").grid(row=row, column=2, sticky="w")

        # Output dir
        row += 1
        ttk.Label(frm, text="Directorio salida:").grid(row=row, column=0, sticky="w", pady=(8, 0))
        self.output_dir_var = tk.StringVar(value=str(self.script_dir))
        out_entry = ttk.Entry(frm, textvariable=self.output_dir_var, width=40)
        out_entry.grid(row=row, column=1, sticky="w", padx=5, pady=(8, 0))
        ttk.Button(frm, text="Examinar…", command=self.browse_output_dir).grid(row=row, column=2, sticky="w", pady=(8, 0))

        # Options
        row += 1
        self.text_output_var = tk.BooleanVar(value=True)
        self.single_file_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Salida en texto", variable=self.text_output_var).grid(row=row, column=0, sticky="w", pady=(8, 0))
        ttk.Checkbutton(frm, text="Un solo archivo", variable=self.single_file_var).grid(row=row, column=1, sticky="w", pady=(8, 0))

        # Buttons
        row += 1
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.start_btn = ttk.Button(btns, text="Iniciar monitoreo", command=self.start_monitoring)
        self.stop_btn = ttk.Button(btns, text="Detener monitoreo", command=self.stop_monitoring, state="disabled")
        status_btn = ttk.Button(btns, text="Ver estado", command=self.check_status)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn.pack(side="left", padx=5)
        status_btn.pack(side="left", padx=5)

        # Output area
        row += 1
        self.monitor_output = scrolledtext.ScrolledText(frm, height=22, wrap=tk.WORD)
        self.monitor_output.grid(row=row, column=0, columnspan=3, sticky="nsew", pady=(10, 0))
        frm.rowconfigure(row, weight=1)
        frm.columnconfigure(1, weight=1)

    def setup_analysis_tab(self):
        frm = ttk.Frame(self.tab_analysis, padding=10)
        frm.pack(fill="both", expand=True)

        row = 0
        ttk.Label(frm, text="Directorio de capturas:").grid(row=row, column=0, sticky="w")
        self.analysis_path_var = tk.StringVar(value=str(self.script_dir))
        path_entry = ttk.Entry(frm, textvariable=self.analysis_path_var, width=50)
        path_entry.grid(row=row, column=1, sticky="w", padx=5)
        ttk.Button(frm, text="Examinar…", command=self.browse_analysis_dir).grid(row=row, column=2, sticky="w")

        # Params
        row += 1
        ttk.Label(frm, text="Top N:").grid(row=row, column=0, sticky="w", pady=(8, 0))
        self.top_var = tk.StringVar(value="10")
        ttk.Entry(frm, textvariable=self.top_var, width=6).grid(row=row, column=1, sticky="w", padx=5, pady=(8, 0))

        row += 1
        ttk.Label(frm, text="Umbral sospechoso (MB):").grid(row=row, column=0, sticky="w")
        self.threshold_var = tk.StringVar(value="50")
        ttk.Entry(frm, textvariable=self.threshold_var, width=8).grid(row=row, column=1, sticky="w", padx=5)

        row += 1
        ttk.Label(frm, text="Máx. PCAPs a analizar:").grid(row=row, column=0, sticky="w")
        self.max_pcaps_var = tk.StringVar(value="5")
        ttk.Entry(frm, textvariable=self.max_pcaps_var, width=8).grid(row=row, column=1, sticky="w", padx=5)

        row += 1
        self.skip_pcap_var = tk.BooleanVar(value=False)
        self.json_output_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Saltar análisis PCAP", variable=self.skip_pcap_var).grid(row=row, column=0, sticky="w", pady=(8, 0))
        ttk.Checkbutton(frm, text="Salida JSON", variable=self.json_output_var).grid(row=row, column=1, sticky="w", pady=(8, 0))

        # Buttons
        row += 1
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.analyze_btn = ttk.Button(btns, text="Analizar capturas", command=self.run_analysis)
        self.analyze_btn.pack(side="left", padx=5)
        self.cancel_btn = ttk.Button(btns, text="Cancelar", command=self.cancel_analysis, state="disabled")
        self.cancel_btn.pack(side="left", padx=5)
        self.copy_btn = ttk.Button(btns, text="Copiar texto", command=self.copy_analysis_output)
        self.copy_btn.pack(side="left", padx=5)

        # Output area
        row += 1
        self.analysis_output = scrolledtext.ScrolledText(frm, height=22, wrap=tk.WORD)
        self.analysis_output.grid(row=row, column=0, columnspan=3, sticky="nsew", pady=(10, 0))
        frm.rowconfigure(row, weight=1)
        frm.columnconfigure(1, weight=1)

        # Keybindings for copy
        self.analysis_output.bind("<Control-c>", self.copy_analysis_output)
        if sys.platform == "darwin":
            self.analysis_output.bind("<Command-c>", self.copy_analysis_output)

    # ============================ HELPERS ============================
    def on_mode_change(self, _evt=None):
        if self.mode_var.get() == "custom":
            self.ports_entry.configure(state="normal")
        else:
            self.ports_entry.configure(state="disabled")

    def detect_interfaces(self):
        """Detecta interfaces y permite seleccionar una."""
        try:
            # Prefer ip -o link to list names
            proc = subprocess.run(["bash", "-lc", "ip -o link show | awk -F': ' '{print $2}' | grep -v lo"],
                                  capture_output=True, text=True, timeout=5)
            names = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
            if not names:
                messagebox.showwarning("Advertencia", "No se encontraron interfaces (excluyendo lo)")
                return
            choice = self.show_interface_dialog(names)
            if choice:
                self.interface_var.set(choice)
        except Exception as e:
            messagebox.showerror("Error", f"Error detectando interfaces: {e}")

    def show_interface_dialog(self, items: List[str]) -> Optional[str]:
        dialog = tk.Toplevel(self.root)
        dialog.title("Seleccionar interfaz")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("350x300")

        ttk.Label(dialog, text="Seleccione una interfaz:").pack(pady=8)
        lb = tk.Listbox(dialog, height=10)
        for it in items:
            lb.insert(tk.END, it)
        lb.pack(fill="both", expand=True, padx=10)

        result = {"val": None}

        def accept():
            sel = lb.curselection()
            if sel:
                result["val"] = lb.get(sel[0])
                dialog.destroy()
            else:
                messagebox.showwarning("Advertencia", "Seleccione una interfaz")

        def on_dbl(_e):
            accept()

        lb.bind("<Double-Button-1>", on_dbl)

        btns = ttk.Frame(dialog)
        btns.pack(pady=8)
        ttk.Button(btns, text="Seleccionar", command=accept).pack(side="left", padx=5)
        ttk.Button(btns, text="Cancelar", command=dialog.destroy).pack(side="left", padx=5)

        dialog.wait_window()
        return result["val"]

    def browse_output_dir(self):
        directory = filedialog.askdirectory(initialdir=self.output_dir_var.get())
        if directory:
            self.output_dir_var.set(directory)

    def browse_analysis_dir(self):
        directory = filedialog.askdirectory(initialdir=self.analysis_path_var.get())
        if directory:
            self.analysis_path_var.set(directory)

    def log_monitor(self, text: str):
        def _append():
            self.monitor_output.insert(tk.END, text)
            self.monitor_output.see(tk.END)
        self.root.after(0, _append)

    def log_analysis(self, text: str):
        def _append():
            self.analysis_output.insert(tk.END, text)
            self.analysis_output.see(tk.END)
        self.root.after(0, _append)

    # ============================ MONITOR ============================
    def start_monitoring(self):
        if not self.interface_var.get():
            messagebox.showerror("Error", "Debe especificar una interfaz de red")
            return
        if self.mode_var.get() == "custom" and not self.ports_var.get():
            messagebox.showerror("Error", "Modo custom requiere especificar puertos")
            return

        script_path = self.script_dir / "monitor_ports.sh"
        if not script_path.exists():
            messagebox.showerror("Error", f"No se encuentra el script: {script_path}")
            return

        cmd = ["sudo", str(script_path), "-m", self.mode_var.get(), "-i", self.interface_var.get(), "-o", self.output_dir_var.get()]
        if self.mode_var.get() == "custom":
            cmd += ["-p", self.ports_var.get()]
        if self.text_output_var.get():
            cmd.append("-t")
        if self.single_file_var.get():
            cmd.append("-f")

        self.monitor_output.delete(1.0, tk.END)
        self.log_monitor("═══════════════════════════════════════════════════\n")
        self.log_monitor(f"Ejecutando: {' '.join(cmd)}\n")
        self.log_monitor("═══════════════════════════════════════════════════\n\n")
        self.log_monitor("[INFO] Iniciando monitoreo de puertos...\n\n")

        def run():
            try:
                self.monitor_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                )
                self.log_monitor(f"[OK] Proceso iniciado (PID: {self.monitor_process.pid})\n\n")
                while True:
                    line = self.monitor_process.stdout.readline()
                    if not line:
                        if self.monitor_process.poll() is not None:
                            break
                        continue
                    self.log_monitor(line)

                rc = self.monitor_process.wait()
                if rc == 0:
                    self.log_monitor("\n[OK] Monitoreo iniciado correctamente.\n")
                    self.log_monitor("[INFO] Los procesos de captura están corriendo en background.\n")
                    self.log_monitor("[INFO] Usa 'Ver estado' para verificar o 'Detener' para finalizar.\n")
                else:
                    self.log_monitor(f"\n[ERROR] El proceso terminó con código: {rc}\n")
                self.log_monitor("\n═══════════════════════════════════════════════════\n")
            except Exception as e:
                self.log_monitor(f"\n[ERROR] {e}\n")
            finally:
                self.is_monitoring = False
                self.root.after(0, self.update_monitor_buttons)

        self.is_monitoring = True
        self.update_monitor_buttons()
        threading.Thread(target=run, daemon=True).start()

    def stop_monitoring(self):
        script_path = self.script_dir / "monitor_ports.sh"
        try:
            result = subprocess.run(["sudo", str(script_path), "--stop"], capture_output=True, text=True, timeout=10)
            self.log_monitor("\n═══════════════════════════════════════════════════\n")
            self.log_monitor("[INFO] Comando de detención enviado\n")
            if result.stdout:
                self.log_monitor(result.stdout)
            self.log_monitor("═══════════════════════════════════════════════════\n")
        except Exception as e:
            messagebox.showerror("Error", f"Error al detener monitoreo: {e}")
        finally:
            self.is_monitoring = False
            self.update_monitor_buttons()

    def check_status(self):
        script_path = self.script_dir / "monitor_ports.sh"
        try:
            result = subprocess.run(["sudo", str(script_path), "--status"], capture_output=True, text=True, timeout=10)
            self.log_monitor(f"\n--- Estado ---\n{result.stdout}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar estado: {e}")

    def update_monitor_buttons(self):
        if self.is_monitoring:
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
        else:
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    # ============================ ANALYSIS ============================
    def run_analysis(self):
        analysis_script = self.script_dir / "analyze_captures.py"
        if not analysis_script.exists():
            messagebox.showerror("Error", f"No se encuentra el script: {analysis_script}")
            return

        capture_path_str = os.path.expanduser(self.analysis_path_var.get())
        capture_path = Path(capture_path_str)
        if not capture_path.exists():
            messagebox.showerror("Error", f"El directorio no existe: {capture_path}")
            return
        capture_path_abs = str(capture_path.resolve())

        cmd = [sys.executable, "-u", str(analysis_script), "--path", capture_path_abs]
        try:
            cmd += ["--top", str(int(self.top_var.get()))]
        except ValueError:
            messagebox.showerror("Error", "Top N debe ser un número entero")
            return
        try:
            cmd += ["--suspect-threshold", str(float(self.threshold_var.get()))]
        except ValueError:
            messagebox.showerror("Error", "Umbral debe ser un número decimal")
            return
        try:
            cmd += ["--max-pcaps", str(int(self.max_pcaps_var.get()))]
        except ValueError:
            messagebox.showerror("Error", "Max PCAPs debe ser un número entero")
            return
        if self.skip_pcap_var.get():
            cmd.append("--skip-pcap")
        if self.json_output_var.get():
            cmd.append("--json")

        # Clear and header
        self.analysis_output.delete(1.0, tk.END)
        self.log_analysis("\n")
        self.log_analysis("╔═══════════════════════════════════════════════════════════════╗\n")
        self.log_analysis("║           ANÁLISIS DE CAPTURAS DE TRÁFICO DE RED              ║\n")
        self.log_analysis("╚═══════════════════════════════════════════════════════════════╝\n\n")
        self.log_analysis(f"📁 Directorio: {capture_path_abs}\n")
        self.log_analysis(f"🔝 Top N: {self.top_var.get()}\n")
        self.log_analysis(f"⚠️  Umbral sospechoso: {self.threshold_var.get()} MB\n")
        self.log_analysis(f"📦 Max PCAPs: {self.max_pcaps_var.get()}\n\n")
        self.log_analysis("─" * 65 + "\n")
        self.log_analysis(f"Comando: {' '.join(cmd)}\n")
        self.log_analysis("─" * 65 + "\n\n")
        self.log_analysis("⏳ Analizando capturas... Por favor espere...\n\n")

        self.analyze_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.analysis_process = None

        def run():
            import time
            start = time.time()
            captured_lines: List[str] = []
            try:
                env = os.environ.copy()
                env.setdefault("PYTHONUNBUFFERED", "1")
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=str(self.script_dir),
                    env=env,
                )
                self.analysis_process = process
                self.log_analysis(f"[PID] {process.pid}\n")

                last_output = [time.time()]

                def heartbeat():
                    while True:
                        if process.poll() is not None:
                            break
                        if time.time() - last_output[0] > 2.5:  # 2.5s sin output
                            self.log_analysis(".")
                            last_output[0] = time.time()
                        time.sleep(2.5)

                threading.Thread(target=heartbeat, daemon=True).start()

                # Drain stderr in separate thread
                stderr_lines: List[str] = []
                def drain_stderr():
                    for err_line in iter(process.stderr.readline, ''):
                        if err_line:
                            stderr_lines.append(err_line)
                            self.log_analysis(err_line)
                            last_output[0] = time.time()
                t_err = threading.Thread(target=drain_stderr, daemon=True)
                t_err.start()

                # Read stdout
                for line in iter(process.stdout.readline, ''):
                    if line:
                        captured_lines.append(line)
                        self.log_analysis(line)
                        last_output[0] = time.time()
                process.stdout.close()
                t_err.join(timeout=1)
                rc = process.wait()
                elapsed = time.time() - start

                self.log_analysis("\n" + "═" * 65 + "\n")
                if rc == 0:
                    self.log_analysis(f"⏱️  Tiempo transcurrido: {elapsed:.2f} s\n")
                    try:
                        reports = sorted(capture_path.glob('analysis_report_*.txt'), key=lambda p: p.stat().st_mtime, reverse=True)
                        if reports:
                            latest = reports[0]
                            content = latest.read_text(errors='ignore')
                            self.log_analysis("\n" + "═" * 65 + "\nINFORME FINAL\n" + content + "\n")
                    except Exception:
                        pass
                    self.log_analysis("\n✅ ANÁLISIS COMPLETADO EXITOSAMENTE\n")
                else:
                    self.log_analysis(f"\n❌ Código de salida: {rc}\n")
            except Exception as e:
                self.log_analysis(f"\n❌ ERROR INESPERADO: {e}\n")
            finally:
                self.root.after(0, lambda: (self.analyze_btn.config(state="normal"), self.cancel_btn.config(state="disabled")))
                self.analysis_process = None

        threading.Thread(target=run, daemon=True).start()

    def cancel_analysis(self):
        proc = getattr(self, 'analysis_process', None)
        if proc and proc.poll() is None:
            try:
                proc.kill()
                self.log_analysis("\n❌ Análisis cancelado por el usuario\n")
            except Exception as e:
                self.log_analysis(f"\n[ERROR] No se pudo cancelar: {e}\n")
        self.cancel_btn.config(state="disabled")
        self.analyze_btn.config(state="normal")
        self.analysis_process = None

    def copy_analysis_output(self, event=None):
        try:
            selected = self.analysis_output.selection_get()
        except tk.TclError:
            selected = self.analysis_output.get(1.0, tk.END).strip()
        if not selected:
            return "break" if event else None
        self.root.clipboard_clear()
        self.root.clipboard_append(selected)
        self.root.update_idletasks()
        return "break" if event else None


def main():
    root = tk.Tk()
    app = PortMonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
