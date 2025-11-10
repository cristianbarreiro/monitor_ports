#!/usr/bin/env python3
"""Interfaz gráfica Tkinter para monitor_ports.sh y analyze_captures.py"""

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, scrolledtext, messagebox, filedialog
from typing import Optional


class PortMonitorGUI:
    """Interfaz gráfica para el monitor de puertos"""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Monitor de Puertos - GUI")
        self.root.geometry("500x700")
        
        # Variables de estado
        self.monitor_process: Optional[subprocess.Popen] = None
        self.is_monitoring = False
        self.script_dir = Path(__file__).parent.absolute()
        
        # Configurar UI
        self.setup_ui()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Frame principal con notebook (pestañas)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Pestaña 1: Monitoreo
        monitor_frame = ttk.Frame(notebook)
        notebook.add(monitor_frame, text="Monitoreo")
        self.setup_monitor_tab(monitor_frame)
        
        # Pestaña 2: Análisis
        analysis_frame = ttk.Frame(notebook)
        notebook.add(analysis_frame, text="Análisis")
        self.setup_analysis_tab(analysis_frame)
        
    def setup_monitor_tab(self, parent):
        """Configura la pestaña de monitoreo"""
        # Frame de configuración
        config_frame = ttk.LabelFrame(parent, text="Configuración de Captura", padding=10)
        config_frame.pack(fill="x", padx=5, pady=5)
        
        # Modo
        row = 0
        ttk.Label(config_frame, text="Modo:").grid(row=row, column=0, sticky="w", pady=2)
        self.mode_var = tk.StringVar(value="all")
        mode_combo = ttk.Combobox(config_frame, textvariable=self.mode_var, 
                                  values=["all", "listening", "custom"], 
                                  state="readonly", width=15)
        mode_combo.grid(row=row, column=1, sticky="w", pady=2)
        mode_combo.bind("<<ComboboxSelected>>", self.on_mode_change)
        
        # Interfaz de red
        row += 1
        ttk.Label(config_frame, text="Interfaz:").grid(row=row, column=0, sticky="w", pady=2)
        self.interface_var = tk.StringVar()
        interface_entry = ttk.Entry(config_frame, textvariable=self.interface_var, width=20)
        interface_entry.grid(row=row, column=1, sticky="w", pady=2)
        ttk.Button(config_frame, text="Detectar", command=self.detect_interfaces).grid(row=row, column=2, padx=5)
        
        # Puertos personalizados (solo para modo custom)
        row += 1
        ttk.Label(config_frame, text="Puertos (custom):").grid(row=row, column=0, sticky="w", pady=2)
        self.ports_var = tk.StringVar()
        self.ports_entry = ttk.Entry(config_frame, textvariable=self.ports_var, width=30)
        self.ports_entry.grid(row=row, column=1, columnspan=2, sticky="w", pady=2)
        self.ports_entry.config(state="disabled")
        
        # Directorio de salida
        row += 1
        ttk.Label(config_frame, text="Dir. Salida:").grid(row=row, column=0, sticky="w", pady=2)
        self.output_dir_var = tk.StringVar(value="./capturas")
        ttk.Entry(config_frame, textvariable=self.output_dir_var, width=30).grid(row=row, column=1, sticky="w", pady=2)
        ttk.Button(config_frame, text="Explorar", command=self.browse_output_dir).grid(row=row, column=2, padx=5)
        
        # Opciones adicionales
        row += 1
        self.text_output_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(config_frame, text="Generar salida de texto (.log)", 
                       variable=self.text_output_var).grid(row=row, column=0, columnspan=2, sticky="w", pady=2)
        
        row += 1
        self.single_file_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="Un solo archivo (en vez de por puerto)", 
                       variable=self.single_file_var).grid(row=row, column=0, columnspan=2, sticky="w", pady=2)
        
        # Frame de control
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="Iniciar Monitoreo", 
                                    command=self.start_monitoring, style="Accent.TButton")
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Detener Monitoreo", 
                                   command=self.stop_monitoring, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        self.status_btn = ttk.Button(control_frame, text="Ver Estado", 
                                     command=self.check_status)
        self.status_btn.pack(side="left", padx=5)
        
        # Frame de salida
        output_frame = ttk.LabelFrame(parent, text="Salida del Monitor", padding=5)
        output_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.monitor_output = scrolledtext.ScrolledText(output_frame, height=15, wrap=tk.WORD)
        self.monitor_output.pack(fill="both", expand=True)
        
    def setup_analysis_tab(self, parent):
        """Configura la pestaña de análisis"""
        # Frame de configuración del análisis
        config_frame = ttk.LabelFrame(parent, text="Configuración de Análisis", padding=10)
        config_frame.pack(fill="x", padx=5, pady=5)
        
        # Directorio de capturas
        row = 0
        ttk.Label(config_frame, text="Dir. Capturas:").grid(row=row, column=0, sticky="w", pady=2)
        self.analysis_path_var = tk.StringVar(value="./capturas")
        ttk.Entry(config_frame, textvariable=self.analysis_path_var, width=40).grid(row=row, column=1, sticky="w", pady=2)
        ttk.Button(config_frame, text="Explorar", command=self.browse_analysis_dir).grid(row=row, column=2, padx=5)
        
        # Top N
        row += 1
        ttk.Label(config_frame, text="Top N:").grid(row=row, column=0, sticky="w", pady=2)
        self.top_var = tk.StringVar(value="10")
        ttk.Entry(config_frame, textvariable=self.top_var, width=10).grid(row=row, column=1, sticky="w", pady=2)
        
        # Umbral de sospechosos (MB)
        row += 1
        ttk.Label(config_frame, text="Umbral sospechoso (MB):").grid(row=row, column=0, sticky="w", pady=2)
        self.threshold_var = tk.StringVar(value="5.0")
        ttk.Entry(config_frame, textvariable=self.threshold_var, width=10).grid(row=row, column=1, sticky="w", pady=2)
        
        # Max pcaps a analizar
        row += 1
        ttk.Label(config_frame, text="Max PCAPs:").grid(row=row, column=0, sticky="w", pady=2)
        self.max_pcaps_var = tk.StringVar(value="1")
        ttk.Entry(config_frame, textvariable=self.max_pcaps_var, width=10).grid(row=row, column=1, sticky="w", pady=2)
        
        # Opciones
        row += 1
        self.skip_pcap_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(config_frame, text="Omitir análisis de PCAPs (tshark/capinfos)", 
                       variable=self.skip_pcap_var).grid(row=row, column=0, columnspan=2, sticky="w", pady=2)
        
        row += 1
        self.json_output_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(config_frame, text="Incluir salida JSON", 
                       variable=self.json_output_var).grid(row=row, column=0, columnspan=2, sticky="w", pady=2)
        
        # Frame de control
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        self.analyze_btn = ttk.Button(control_frame, text="Ejecutar Análisis", 
                                      command=self.run_analysis, style="Accent.TButton")
        self.analyze_btn.pack(side="left", padx=5)
        
        ttk.Button(control_frame, text="Limpiar Salida", 
                  command=lambda: self.analysis_output.delete(1.0, tk.END)).pack(side="left", padx=5)
        
        # Frame de salida
        output_frame = ttk.LabelFrame(parent, text="Resultados del Análisis", padding=5)
        output_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.analysis_output = scrolledtext.ScrolledText(output_frame, height=20, wrap=tk.WORD)
        self.analysis_output.pack(fill="both", expand=True)
        
    def on_mode_change(self, event=None):
        """Habilita/deshabilita el campo de puertos según el modo"""
        if self.mode_var.get() == "custom":
            self.ports_entry.config(state="normal")
        else:
            self.ports_entry.config(state="disabled")
            
    def detect_interfaces(self):
        """Detecta interfaces de red disponibles"""
        try:
            result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split("\n"):
                if ": " in line and "state" in line.lower():
                    parts = line.split(": ")
                    if len(parts) >= 2:
                        iface = parts[1].split(":")[0].strip()
                        if iface not in ["lo"]:
                            interfaces.append(iface)
            
            if interfaces:
                if len(interfaces) == 1:
                    # Si solo hay una interfaz, seleccionarla automáticamente
                    self.interface_var.set(interfaces[0])
                    messagebox.showinfo("Interfaz detectada", 
                                       f"Interfaz seleccionada automáticamente: {interfaces[0]}")
                else:
                    # Mostrar diálogo para seleccionar
                    choice = self.show_interface_dialog(interfaces)
                    if choice:
                        self.interface_var.set(choice)
            else:
                messagebox.showwarning("Advertencia", "No se detectaron interfaces de red (excepto lo)")
        except Exception as e:
            messagebox.showerror("Error", f"Error al detectar interfaces: {e}")
            
    def show_interface_dialog(self, interfaces):
        """Muestra un diálogo para seleccionar una interfaz"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Seleccionar Interfaz")
        dialog.geometry("350x250")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Interfaces de red disponibles:", 
                 font=('', 10, 'bold')).pack(pady=10)
        
        # Frame para el listbox
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, 
                            font=('', 10), selectmode=tk.SINGLE)
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=listbox.yview)
        
        for iface in interfaces:
            listbox.insert(tk.END, iface)
        
        # Seleccionar el primero por defecto
        if interfaces:
            listbox.selection_set(0)
            
        result = [None]
        
        def on_select():
            selection = listbox.curselection()
            if selection:
                result[0] = listbox.get(selection[0])
                dialog.destroy()
            else:
                messagebox.showwarning("Advertencia", "Debe seleccionar una interfaz")
        
        def on_double_click(event):
            selection = listbox.curselection()
            if selection:
                result[0] = listbox.get(selection[0])
                dialog.destroy()
        
        listbox.bind('<Double-Button-1>', on_double_click)
        
        # Frame para botones
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Seleccionar", command=on_select).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancelar", command=dialog.destroy).pack(side="left", padx=5)
        
        dialog.wait_window()
        return result[0]
        
    def browse_output_dir(self):
        """Abre diálogo para seleccionar directorio de salida"""
        directory = filedialog.askdirectory(initialdir=self.output_dir_var.get())
        if directory:
            self.output_dir_var.set(directory)
            
    def browse_analysis_dir(self):
        """Abre diálogo para seleccionar directorio de análisis"""
        directory = filedialog.askdirectory(initialdir=self.analysis_path_var.get())
        if directory:
            self.analysis_path_var.set(directory)
            
    def start_monitoring(self):
        """Inicia el monitoreo de puertos"""
        # Validar campos
        if not self.interface_var.get():
            messagebox.showerror("Error", "Debe especificar una interfaz de red")
            return
            
        if self.mode_var.get() == "custom" and not self.ports_var.get():
            messagebox.showerror("Error", "Modo custom requiere especificar puertos")
            return
            
        # Construir comando
        script_path = self.script_dir / "monitor_ports.sh"
        if not script_path.exists():
            messagebox.showerror("Error", f"No se encuentra el script: {script_path}")
            return
            
        cmd = ["sudo", str(script_path)]
        cmd.extend(["-m", self.mode_var.get()])
        cmd.extend(["-i", self.interface_var.get()])
        cmd.extend(["-o", self.output_dir_var.get()])
        
        if self.mode_var.get() == "custom":
            cmd.extend(["-p", self.ports_var.get()])
            
        if self.text_output_var.get():
            cmd.append("-t")
            
        if self.single_file_var.get():
            cmd.append("-f")
            
        # Limpiar salida
        self.monitor_output.delete(1.0, tk.END)
        self.log_monitor(f"═══════════════════════════════════════════════════\n")
        self.log_monitor(f"Ejecutando: {' '.join(cmd)}\n")
        self.log_monitor(f"═══════════════════════════════════════════════════\n\n")
        self.log_monitor(f"[INFO] Iniciando monitoreo de puertos...\n\n")
        
        # Ejecutar en thread
        def run():
            import select
            import os
            
            try:
                # Usar unbuffered mode para captura en tiempo real
                self.monitor_process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=0,  # Sin buffer para actualizaciones inmediatas
                    universal_newlines=True
                )
                
                self.log_monitor(f"[OK] Proceso iniciado (PID: {self.monitor_process.pid})\n\n")
                
                # Leer salida línea por línea en tiempo real
                while True:
                    line = self.monitor_process.stdout.readline()
                    if not line:
                        if self.monitor_process.poll() is not None:
                            break
                        continue
                    
                    self.log_monitor(line)
                    
                return_code = self.monitor_process.wait()
                
                if return_code == 0:
                    self.log_monitor("\n[OK] Monitoreo iniciado correctamente.\n")
                    self.log_monitor("[INFO] Los procesos de captura están corriendo en background.\n")
                    self.log_monitor("[INFO] Usa el botón 'Ver Estado' para verificar el estado.\n")
                    self.log_monitor("[INFO] Usa el botón 'Detener Monitoreo' para finalizar.\n")
                else:
                    self.log_monitor(f"\n[ERROR] El proceso terminó con código: {return_code}\n")
                    
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
        """Detiene el monitoreo de puertos"""
        script_path = self.script_dir / "monitor_ports.sh"
        try:
            result = subprocess.run(["sudo", str(script_path), "--stop"], 
                         capture_output=True, text=True, timeout=5)
            self.log_monitor("\n═══════════════════════════════════════════════════\n")
            self.log_monitor("[INFO] Comando de detención enviado\n")
            if result.stdout:
                self.log_monitor(result.stdout)
            self.log_monitor("═══════════════════════════════════════════════════\n")
            
            # Actualizar estado para permitir nuevo monitoreo
            self.is_monitoring = False
            self.update_monitor_buttons()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al detener monitoreo: {e}")
            self.is_monitoring = False
            self.update_monitor_buttons()
            
    def check_status(self):
        """Verifica el estado del monitoreo"""
        script_path = self.script_dir / "monitor_ports.sh"
        try:
            result = subprocess.run(["sudo", str(script_path), "--status"], 
                                  capture_output=True, text=True, timeout=5)
            self.log_monitor(f"\n--- Estado ---\n{result.stdout}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar estado: {e}")
            
    def run_analysis(self):
        """Ejecuta el análisis de capturas"""
        analysis_script = self.script_dir / "analyze_captures.py"
        if not analysis_script.exists():
            messagebox.showerror("Error", f"No se encuentra el script: {analysis_script}")
            return
        
        # Validar que existe el directorio de capturas
        capture_path = Path(self.analysis_path_var.get())
        if not capture_path.exists():
            messagebox.showerror("Error", f"El directorio no existe: {capture_path}")
            return
            
        # Construir comando
        cmd = [sys.executable, str(analysis_script)]
        cmd.extend(["--path", self.analysis_path_var.get()])
        
        try:
            top_n = int(self.top_var.get())
            cmd.extend(["--top", str(top_n)])
        except ValueError:
            messagebox.showerror("Error", "Top N debe ser un número entero")
            return
            
        try:
            threshold = float(self.threshold_var.get())
            cmd.extend(["--suspect-threshold", str(threshold)])
        except ValueError:
            messagebox.showerror("Error", "Umbral debe ser un número decimal")
            return
            
        try:
            max_pcaps = int(self.max_pcaps_var.get())
            cmd.extend(["--max-pcaps", str(max_pcaps)])
        except ValueError:
            messagebox.showerror("Error", "Max PCAPs debe ser un número entero")
            return
            
        if self.skip_pcap_var.get():
            cmd.append("--skip-pcap")
            
        if self.json_output_var.get():
            cmd.append("--json")
            
        # Limpiar salida
        self.analysis_output.delete(1.0, tk.END)
        
        # Encabezado visual
        self.log_analysis("\n")
        self.log_analysis("╔═══════════════════════════════════════════════════════════════╗\n")
        self.log_analysis("║           ANÁLISIS DE CAPTURAS DE TRÁFICO DE RED              ║\n")
        self.log_analysis("╚═══════════════════════════════════════════════════════════════╝\n\n")
        
        self.log_analysis(f"📁 Directorio: {self.analysis_path_var.get()}\n")
        self.log_analysis(f"🔝 Top N: {self.top_var.get()}\n")
        self.log_analysis(f"⚠️  Umbral sospechoso: {self.threshold_var.get()} MB\n")
        self.log_analysis(f"📦 Max PCAPs: {self.max_pcaps_var.get()}\n\n")
        
        self.log_analysis("─" * 65 + "\n")
        self.log_analysis(f"Comando: {' '.join(cmd)}\n")
        self.log_analysis("─" * 65 + "\n\n")
        
        self.log_analysis("⏳ Analizando capturas... Por favor espere...\n\n")
        
        # Deshabilitar botón
        self.analyze_btn.config(state="disabled")
        
        # Ejecutar en thread
        def run():
            import time
            start_time = time.time()
            
            try:
                # Ejecutar el análisis con captura de salida en tiempo real
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Leer salida en tiempo real
                stdout_lines = []
                stderr_lines = []
                
                # Leer stdout
                for line in process.stdout:
                    stdout_lines.append(line)
                    self.log_analysis(line)
                
                process.wait()
                
                # Leer stderr si existe
                stderr_content = process.stderr.read()
                if stderr_content:
                    stderr_lines = stderr_content.splitlines(keepends=True)
                
                elapsed_time = time.time() - start_time
                
                # Separador antes del resumen
                self.log_analysis("\n" + "═" * 65 + "\n")
                
                if process.returncode == 0:
                    self.log_analysis("\n✅ ANÁLISIS COMPLETADO EXITOSAMENTE\n\n")
                    self.log_analysis(f"⏱️  Tiempo transcurrido: {elapsed_time:.2f} segundos\n")
                    self.log_analysis(f"📊 Resultados mostrados arriba\n")
                    
                    # Mostrar notificación
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Análisis completado", 
                        f"El análisis se completó exitosamente en {elapsed_time:.1f} segundos"
                    ))
                else:
                    self.log_analysis(f"\n❌ ERROR: El análisis terminó con código: {process.returncode}\n\n")
                    if stderr_lines:
                        self.log_analysis("\n📋 Errores detectados:\n")
                        self.log_analysis("─" * 65 + "\n")
                        for line in stderr_lines:
                            self.log_analysis(line)
                    
                    # Mostrar notificación de error
                    self.root.after(0, lambda: messagebox.showerror(
                        "Error en el análisis", 
                        f"El análisis falló con código {process.returncode}"
                    ))
                    
                self.log_analysis("\n" + "═" * 65 + "\n")
                    
            except subprocess.TimeoutExpired:
                self.log_analysis("\n❌ ERROR: Tiempo de espera excedido (5 minutos)\n")
                self.log_analysis("El análisis tomó demasiado tiempo. Intenta con menos archivos.\n")
                self.root.after(0, lambda: messagebox.showerror(
                    "Timeout", 
                    "El análisis excedió el tiempo límite de 5 minutos"
                ))
            except Exception as e:
                self.log_analysis(f"\n❌ ERROR INESPERADO: {e}\n")
                self.root.after(0, lambda: messagebox.showerror(
                    "Error", 
                    f"Error inesperado durante el análisis: {e}"
                ))
            finally:
                self.root.after(0, lambda: self.analyze_btn.config(state="normal"))
                
        threading.Thread(target=run, daemon=True).start()
        
    def log_monitor(self, text):
        """Agrega texto al área de salida del monitor"""
        def append():
            self.monitor_output.insert(tk.END, text)
            self.monitor_output.see(tk.END)
        self.root.after(0, append)
        
    def log_analysis(self, text):
        """Agrega texto al área de salida del análisis"""
        def append():
            self.analysis_output.insert(tk.END, text)
            self.analysis_output.see(tk.END)
        self.root.after(0, append)
        
    def update_monitor_buttons(self):
        """Actualiza el estado de los botones de monitoreo"""
        if self.is_monitoring:
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
        else:
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")


def main():
    """Función principal"""
    root = tk.Tk()
    app = PortMonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
