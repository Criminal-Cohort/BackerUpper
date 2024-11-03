import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import shutil
import hashlib
import json
import threading
import queue
from datetime import datetime
import logging
import configparser
from concurrent.futures import ThreadPoolExecutor
import io

# Load configuration from an INI file
config = configparser.ConfigParser()
config.read('backup_config.ini')

errors = []


class RobustFileCopy:
    def __init__(self, buffer_size: int = 16 * 1024 * 1024):
        self.buffer_size = buffer_size
        self.logger = logging.getLogger('BackupApp')

    def calculate_checksum(self, filepath: str) -> str:
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(self.buffer_size)
                    if not chunk:
                        break
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating checksum for {filepath}: {str(e)}")
            raise

    def copy_with_verification(self, src: str, dest: str, progress_callback=None, max_retries: int = 3) -> bool:
        retry_count = 0

        try:
            total_size = os.path.getsize(src)
        except OSError as e:
            self.logger.error(f"Error getting file size for {src}: {str(e)}")
            return False

        while retry_count < max_retries:
            try:
                # Ensure destination directory exists
                dest_dir = os.path.dirname(dest)
                if dest_dir:
                    os.makedirs(dest_dir, exist_ok=True)

                copied_size = 0
                with open(src, 'rb') as fsrc:
                    with open(dest, 'wb') as fdst:
                        while True:
                            try:
                                chunk = fsrc.read(self.buffer_size)
                                if not chunk:
                                    break
                                fdst.write(chunk)
                                copied_size += len(chunk)

                                if progress_callback and total_size > 0:
                                    try:
                                        progress = (copied_size / total_size) * 100
                                        progress_callback(min(progress, 100))
                                    except Exception as e:
                                        self.logger.error(f"Progress callback error: {str(e)}")

                            except Exception as e:
                                self.logger.error(f"Error during chunk copy: {str(e)}")
                                raise

                # Basic size verification
                if os.path.getsize(dest) != total_size:
                    raise Exception("Size mismatch after copy")

                # Copy file metadata
                try:
                    shutil.copystat(src, dest)
                except Exception as e:
                    self.logger.warning(f"Failed to copy metadata: {str(e)}")

                return True

            except Exception as e:
                retry_count += 1
                self.logger.error(f"Copy attempt {retry_count} failed for {src}: {str(e)}")

                # Clean up failed copy
                try:
                    if os.path.exists(dest):
                        os.remove(dest)
                except Exception as cleanup_error:
                    self.logger.error(f"Error cleaning up failed copy: {str(cleanup_error)}")

                if retry_count >= max_retries:
                    self.logger.error(f"Failed to copy file after {max_retries} attempts: {src}")
                    return False

        return False


class BackupApp:
    def __init__(self, root):
        self.executor = ThreadPoolExecutor(max_workers=4)  # Reduced number of workers
        self.root = root
        self.root.title("Advanced Backup Software")
        self.root.geometry("800x600")

        self.setup_logging()
        self.file_copier = RobustFileCopy()
        self.setup_styles()
        self.sources = []
        self.dest_path = tk.StringVar()
        self.progress = tk.DoubleVar()
        self.status = tk.StringVar()
        self.status.set("Ready")
        self.preset_name = tk.StringVar()
        self.compression_enabled = tk.BooleanVar(value=False)
        self.verify_enabled = tk.BooleanVar(value=True)
        self.presets = self.load_presets()
        self.setup_gui()
        self.load_config()
        self.active_tasks = set()
        self.cancel_event = threading.Event()

    def setup_logging(self):
        self.logger = logging.getLogger('BackupApp')
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler('backup_app.log')
        fh.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabelframe", background="#f0f0f0")
        self.style.configure("TLabelframe.Label", background="#f0f0f0", font=('Arial', 10, 'bold'))
        self.style.configure("Custom.TButton", padding=5, font=('Arial', 9))

    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill="both", expand=True)

        self.setup_sources_section(main_frame)
        self.setup_destination_section(main_frame)
        self.setup_options_section(main_frame)
        self.setup_presets_section(main_frame)
        self.setup_progress_section(main_frame)
        self.setup_control_buttons(main_frame)
        self.setup_log_section(main_frame)

        self.queue = queue.Queue()
        self.is_running = False

    def setup_sources_section(self, parent):
        sources_frame = ttk.LabelFrame(parent, text="Source Locations", padding="10")
        sources_frame.pack(fill="x", pady=(0, 10))

        sources_list_frame = ttk.Frame(sources_frame)
        sources_list_frame.pack(fill="both", expand=True)

        self.sources_listbox = tk.Listbox(sources_list_frame, height=5, selectmode=tk.SINGLE)
        sources_scrollbar = ttk.Scrollbar(sources_list_frame, orient="vertical", command=self.sources_listbox.yview)

        self.sources_listbox.pack(side="left", fill="both", expand=True)
        sources_scrollbar.pack(side="right", fill="y")
        self.sources_listbox.configure(yscrollcommand=sources_scrollbar.set)

        source_buttons_frame = ttk.Frame(sources_frame)
        source_buttons_frame.pack(fill="x", pady=5)

        ttk.Button(source_buttons_frame, text="Add Folder", command=self.add_source_folder,
                   style="Custom.TButton").pack(side="left", padx=2)
        ttk.Button(source_buttons_frame, text="Add File", command=self.add_source_file, style="Custom.TButton").pack(
            side="left", padx=2)
        ttk.Button(source_buttons_frame, text="Remove Selected", command=self.remove_source,
                   style="Custom.TButton").pack(side="left", padx=2)

    def setup_destination_section(self, parent):
        dest_frame = ttk.LabelFrame(parent, text="Destination", padding="10")
        dest_frame.pack(fill="x", pady=(0, 10))

        ttk.Entry(dest_frame, textvariable=self.dest_path).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(dest_frame, text="Browse", command=self.browse_dest, style="Custom.TButton").pack(side="right")

    def setup_options_section(self, parent):
        options_frame = ttk.LabelFrame(parent, text="Options", padding="10")
        options_frame.pack(fill="x", pady=(0, 10))

        ttk.Checkbutton(options_frame, text="Enable Compression", variable=self.compression_enabled).pack(side="left",
                                                                                                          padx=5)
        ttk.Checkbutton(options_frame, text="Verify Copies", variable=self.verify_enabled).pack(side="left", padx=5)

    def setup_presets_section(self, parent):
        presets_frame = ttk.LabelFrame(parent, text="Presets", padding="10")
        presets_frame.pack(fill="x", pady=(0, 10))

        preset_controls = ttk.Frame(presets_frame)
        preset_controls.pack(fill="x", pady=(0, 5))

        ttk.Label(preset_controls, text="Preset Name:").pack(side="left", padx=(0, 5))
        ttk.Entry(preset_controls, textvariable=self.preset_name).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(preset_controls, text="Save Preset", command=self.save_preset, style="Custom.TButton").pack(
            side="left", padx=2)

        self.preset_combobox = ttk.Combobox(presets_frame, values=list(self.presets.keys()))
        self.preset_combobox.pack(fill="x", pady=5)
        self.preset_combobox.bind('<<ComboboxSelected>>', self.load_preset)

    def setup_progress_section(self, parent):
        progress_frame = ttk.LabelFrame(parent, text="Progress", padding="10")
        progress_frame.pack(fill="x", pady=(0, 10))

        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress, maximum=100)
        self.progress_bar.pack(fill="x", pady=(0, 5))

        self.status_label = ttk.Label(progress_frame, textvariable=self.status, font=('Arial', 9))
        self.status_label.pack()

    def setup_control_buttons(self, parent):
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(button_frame, text="Start Backup", command=self.start_backup, style="Custom.TButton").pack(
            side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel_backup, style="Custom.TButton").pack(side="left",
                                                                                                         padx=5)

    def setup_log_section(self, parent):
        log_frame = ttk.LabelFrame(parent, text="Log", padding="10")
        log_frame.pack(fill="both", expand=True)

        log_container = ttk.Frame(log_frame)
        log_container.pack(fill="both", expand=True)

        self.log_text = tk.Text(log_container, height=15, width=70, font=('Courier', 9))
        log_scrollbar = ttk.Scrollbar(log_container, orient="vertical", command=self.log_text.yview)

        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=log_scrollbar.set)

    def add_source_folder(self):
        path = filedialog.askdirectory()
        if path and path not in self.sources:
            self.sources.append(path)
            self.sources_listbox.insert(tk.END, path)
            self.logger.info(f"Added source folder: {path}")

    def add_source_file(self):
        path = filedialog.askopenfilename()
        if path and path not in self.sources:
            self.sources.append(path)
            self.sources_listbox.insert(tk.END, path)
            self.logger.info(f"Added source file: {path}")

    def remove_source(self):
        selected = self.sources_listbox.curselection()
        if selected:
            source = self.sources_listbox.get(selected)
            self.sources.remove(source)
            self.sources_listbox.delete(selected)
            self.logger.info(f"Removed source: {source}")

    def browse_dest(self):
        path = filedialog.askdirectory()
        if path:
            self.dest_path.set(path)

    def save_preset(self):
        preset_name = self.preset_name.get()
        if not preset_name:
            messagebox.showerror("Error", "Please enter a preset name")
            return

        self.presets[preset_name] = {
            'sources': self.sources,
            'destination': self.dest_path.get(),
            'compression': self.compression_enabled.get(),
            'verification': self.verify_enabled.get()
        }

        self.update_preset_combobox()
        self.save_presets()
        self.logger.info(f"Saved preset: {preset_name}")

    def load_presets(self):
        try:
            with open('backup_presets.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            return {}

    def log_message(self, message):
        # Assuming you have a Text widget for logging
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.yview(tk.END)  # Scroll to the end of the log

    def update_preset_combobox(self):
        self.preset_combobox['values'] = list(self.presets.keys())

    def save_presets(self):
        with open('backup_presets.json', 'w') as f:
            json.dump(self.presets, f, indent=4)

    def load_preset(self, event):
        preset_name = self.preset_combobox.get()
        if preset_name in self.presets:
            preset = self.presets[preset_name]
            self.sources = preset['sources']
            self.dest_path.set(preset['destination'])
            self.compression_enabled.set(preset['compression'])
            self.verify_enabled.set(preset['verify'])
            self.sources_listbox.delete(0, tk.END)
            for source in self.sources:
                self.sources_listbox.insert(tk.END, source)
            self.logger.info(f"Loaded preset: {preset_name}")

    def load_config(self):
        if 'Settings' in config:
            self.dest_path.set(config['Settings'].get('destination', ''))
            sources = config['Settings'].get('sources', '')
            if sources:
                self.sources = sources.split(',')
                for source in self.sources:
                    self.sources_listbox.insert(tk.END, source)
            self.compression_enabled.set(config['Settings'].getboolean('compression', False))
            self.verify_enabled.set(config['Settings'].getboolean('verification', True))

    def start_backup(self):
        if not self.sources:
            messagebox.showerror("Error", "Please add at least one source location")
            return

        if not self.dest_path.get():
            messagebox.showerror("Error", "Please select a destination folder")
            return

        for source in self.sources:
            if not os.path.exists(source):
                messagebox.showerror("Error", f"Source path does not exist: {source}")
                return

        self.is_running = True
        self.progress.set(0)
        self.status.set("Backup in progress...")
        self.log_text.delete(1.0, tk.END)

        backup_thread = threading.Thread(target=self.backup_files)
        backup_thread.start()
        self.root.after(100, self.check_queue)

    def backup_files(self):
        try:
            self.cancel_event.clear()
            dest = self.dest_path.get()
            base_path = self.dest_path.get()
            i = 1
            while True:
                # backup_folder = os.path.join(base_path, f"Backup{i}")
                if not os.path.exists(os.path.join(base_path, f"Backup{i}")):
                    break
                else:
                    i += 1
            backup_dir = os.path.join(base_path, f"Backup{i}")
            os.makedirs(backup_dir, exist_ok=True)

            total_files = sum(len(files) for source in self.sources
                              for _, _, files in os.walk(source))
            processed_files = 0

            def update_progress(file_progress):
                if total_files > 0:
                    total_progress = ((processed_files + file_progress / 100) / total_files) * 100
                    self.queue.put(("progress", min(total_progress, 100)))

            for source in self.sources:
                if self.cancel_event.is_set():
                    break

                for root, _, files in os.walk(source):
                    if self.cancel_event.is_set():
                        break

                    rel_path = os.path.relpath(root, source)
                    dest_root = os.path.join(backup_dir, rel_path)

                    for file in files:
                        if self.cancel_event.is_set():
                            break

                        src_file = os.path.join(root, file)
                        dest_file = os.path.join(dest_root, file)

                        try:
                            success = self.file_copier.copy_with_verification(
                                src_file, dest_file, update_progress)

                            if success:
                                self.queue.put(("log", f"[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]: Copied: {src_file}"))
                            else:
                                self.queue.put(("error", f"[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]: Failed to copy: {src_file}"))

                            processed_files += 1

                        except Exception as e:
                            self.queue.put(("error2", f"Error copying {src_file}: {str(e)}"))
                            self.logger.error(f"Error copying {src_file}: {str(e)}")
                            errors.append(src_file)

            if self.cancel_event.is_set():
                self.queue.put(("status", "Backup cancelled"))
            else:
                self.queue.put(("status", "Backup completed"))

        except Exception as e:
            self.queue.put(("error", f"Backup error: {str(e)}"))
            self.logger.error(f"Backup error: {str(e)}")

        finally:
            self.log_message(f"Failed to Copy: {errors}")
            self.is_running = False

    def cancel_backup(self):
        self.cancel_event.set()
        self.is_running = False
        self.status.set("Cancelling backup...")
        self.logger.info("Backup cancellation requested")

    def copy_file(self, src, dest):
        return self.file_copier.copy_with_verification(src, dest)

    def check_queue(self):
        try:
            while True:
                msg_type, msg_data = self.queue.get_nowait()

                if msg_type == "progress":
                    self.progress.set(msg_data)
                elif msg_type == "status":
                    self.status.set(msg_data)
                elif msg_type == "log":
                    self.log_message(msg_data)
                elif msg_type == "error":
                    self.status.set("Error occurred")
                    messagebox.showerror("Error", msg_data)
                elif msg_type == "error2":
                    self.log_message(f"Error: {msg_data}")

                self.queue.task_done()

        except queue.Empty:
            if self.is_running:
                self.root.after(100, self.check_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = BackupApp(root)
    root.mainloop()