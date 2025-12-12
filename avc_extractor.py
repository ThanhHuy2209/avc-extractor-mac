import os
import sys
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk
import threading

PASSWORD = "1234"

class AVCExtractorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Resolume AVC Path Extractor")
        self.root.configure(bg="white")
        self.root.geometry("1400x800")
        self.root.resizable(True, True)
        
        self.authenticated = False
        self.current_avc_file = None
        # checkboxes: dict category -> dict(full_path -> IntVar)
        self.checkboxes = {}
        self.tables = {}  # Lưu các Treeview
        # all_data: dict category -> list of tuples (stt, folder_path, file_name, var, full_path)
        self.all_data = {}
        self.search_var = tk.StringVar()  # Biến search
        
        self.setup_styles()
        self.setup_ui()
    
    def get_base_dir(self):
    """Trả về thư mục nơi chứa .app (Mac) hoặc .exe (Win) hoặc thư mục code (chạy Python)"""
    if getattr(sys, 'frozen', False):
        # Nếu đã build thành .app hoặc .exe
        return Path(os.path.dirname(sys.executable))
    else:
        # Khi chạy bằng python
        return Path.cwd()
    
    def setup_styles(self):
        """Thiết lập style cho Treeview"""
        style = ttk.Style()
        style.theme_use("clam")
        
        # Style cho Treeview
        style.configure("Custom.Treeview",
                       background="#FFFFFF",
                       foreground="#212529",
                       rowheight=28,
                       fieldbackground="#FFFFFF",
                       borderwidth=0,
                       font=("Segoe UI", 9))
        
        # Style cho Heading
        style.configure("Custom.Treeview.Heading",
                       background="#F8F9FA",
                       foreground="#495057",
                       borderwidth=1,
                       relief="flat",
                       font=("Segoe UI", 10, "bold"))
        
        # Map cho selected row
        style.map('Custom.Treeview',
                 background=[('selected', '#E3F2FD')],
                 foreground=[('selected', '#0D6EFD')])
        
    def setup_ui(self):
        """Thiết lập giao diện"""
        # Header
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="🎬 RESOLUME AVC PATH EXTRACTOR",
            bg="#2c3e50",
            fg="white",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=15)
        
        # Main content frame
        self.content_frame = tk.Frame(self.root, bg="white")
        self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Show login initially
        self.show_login()
        
    def show_login(self):
        """Hiển thị màn hình đăng nhập"""
        self.clear_content()
        
        login_frame = tk.Frame(self.content_frame, bg="white")
        login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        tk.Label(
            login_frame,
            text="🔒 Nhập mật khẩu để tiếp tục",
            bg="white",
            fg="#2c3e50",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=20)
        
        self.password_entry = tk.Entry(
            login_frame,
            show="*",
            font=("Segoe UI", 12),
            width=25,
            relief="solid",
            borderwidth=1
        )
        self.password_entry.pack(pady=10)
        self.password_entry.bind("<Return>", lambda e: self.check_password())
        
        tk.Button(
            login_frame,
            text="Xác nhận",
            command=self.check_password,
            bg="#3498db",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=15,
            height=2,
            relief="flat",
            cursor="hand2"
        ).pack(pady=15)
        
        self.password_entry.focus()
        
    def check_password(self):
        """Kiểm tra mật khẩu"""
        if self.password_entry.get() == PASSWORD:
            self.authenticated = True
            self.show_main_screen()
        else:
            messagebox.showerror("Lỗi", "Sai mật khẩu!")
            self.password_entry.delete(0, tk.END)
            
    def show_main_screen(self):
        """Hiển thị màn hình chính"""
        self.clear_content()
        
        # Toolbar với nút Refresh
        toolbar = tk.Frame(self.content_frame, bg="white")
        toolbar.pack(fill="x", pady=(0, 10))
        
        # Left side - Refresh button
        left_toolbar = tk.Frame(toolbar, bg="white")
        left_toolbar.pack(side="left")
        
        self.refresh_btn = tk.Button(
            left_toolbar,
            text="🔄 Refresh",
            command=self.refresh_scan,
            bg="#27ae60",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            padx=15,
            pady=5
        )
        self.refresh_btn.pack(side="left")
        
        # File info label
        self.file_info_label = tk.Label(
            left_toolbar,
            text="",
            bg="white",
            fg="#7f8c8d",
            font=("Segoe UI", 9)
        )
        self.file_info_label.pack(side="left", padx=15)
        
        # Right side - Search box
        right_toolbar = tk.Frame(toolbar, bg="white")
        right_toolbar.pack(side="right")
        
        tk.Label(
            right_toolbar,
            text="🔍 Search:",
            bg="white",
            fg="#495057",
            font=("Segoe UI", 10)
        ).pack(side="left", padx=(0, 5))
        
        self.search_entry = tk.Entry(
            right_toolbar,
            textvariable=self.search_var,
            font=("Segoe UI", 10),
            width=30,
            relief="solid",
            borderwidth=1
        )
        self.search_entry.pack(side="left", padx=(0, 5))
        # mỗi khi search_var thay đổi sẽ gọi filter_tables
        self.search_var.trace("w", lambda *args: self.filter_tables())
        
        tk.Button(
            right_toolbar,
            text="✗",
            command=self.clear_search,
            bg="#DC3545",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=3
        ).pack(side="left")
        
        # Spinner frame (ẩn mặc định)
        self.spinner_frame = tk.Frame(self.content_frame, bg="white")
        
        self.spinner_label = tk.Label(
            self.spinner_frame,
            text="⏳ Đang xử lý...",
            bg="white",
            fg="#3498db",
            font=("Segoe UI", 12, "bold")
        )
        self.spinner_label.pack(pady=20)
        
        self.progress = ttk.Progressbar(
            self.spinner_frame,
            mode='indeterminate',
            length=300
        )
        self.progress.pack(pady=10)
        
        # Results frame với canvas để scroll
        self.results_outer_frame = tk.Frame(self.content_frame, bg="white")
        self.results_outer_frame.pack(fill="both", expand=True)
        
        # Canvas và Scrollbar
        self.canvas = tk.Canvas(self.results_outer_frame, bg="white", highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.results_outer_frame, orient="vertical", command=self.canvas.yview)
        
        self.results_frame = tk.Frame(self.canvas, bg="white")
        
        self.results_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.results_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mouse wheel
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Start scanning
        self.scan_avc_files()
        
    def _on_mousewheel(self, event):
        """Xử lý scroll chuột"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
    def create_section_table(self, parent, title, icon, category_key, count):
        """Tạo một bảng cho một section"""
        # Container frame để căn giữa
        container_frame = tk.Frame(parent, bg="white")
        container_frame.pack(fill="x", expand=False, pady=(0, 20))
        
        # Section frame - giới hạn chiều rộng và căn giữa
        section_frame = tk.Frame(container_frame, bg="white")
        section_frame.pack(anchor="center", padx=150)  # padx=150 tạo lề đều hai bên
        
        # Title bar với nút Select/Deselect
        title_bar = tk.Frame(section_frame, bg="white")
        title_bar.pack(fill="x", pady=(0, 5))
        
        tk.Label(
            title_bar,
            text=f"{icon} {title} ({count})",
            bg="white",
            fg="#212529",
            font=("Segoe UI", 12, "bold")
        ).pack(side="left")
        
        # Nút Select/Deselect cho section này
        btn_frame = tk.Frame(title_bar, bg="white")
        btn_frame.pack(side="right")
        
        tk.Button(
            btn_frame,
            text="✓ All",
            command=lambda: self.select_section(category_key),
            bg="#0D6EFD",
            fg="white",
            font=("Segoe UI", 8),
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=2
        ).pack(side="left", padx=2)
        
        tk.Button(
            btn_frame,
            text="✗ None",
            command=lambda: self.deselect_section(category_key),
            bg="#DC3545",
            fg="white",
            font=("Segoe UI", 8),
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=2
        ).pack(side="left", padx=2)
        
        # Table frame
        table_frame = tk.Frame(section_frame, bg="#E9ECEF", relief="solid", borderwidth=1)
        table_frame.pack(fill="both", expand=False)  # Không expand để giữ kích thước
        
        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical")
        hsb = ttk.Scrollbar(table_frame, orient="horizontal")
        
        # Treeview
        columns = ("STT", "Folder Path", "File Name", "Selected")
        tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="tree headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            selectmode="browse",
            style="Custom.Treeview",
            height=min(count, 10)
        )
        
        tree.column("#0", width=0, stretch=False)
        tree.heading("#0", text="")
        
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        
        # Định nghĩa columns
        tree.heading("STT", text="STT")
        tree.heading("Folder Path", text="Folder Path")
        tree.heading("File Name", text="File Name")
        tree.heading("Selected", text="✓")
        
        # Cấu hình độ rộng cột cố định
        tree.column("STT", width=60, anchor="center", minwidth=60, stretch=False)
        tree.column("Folder Path", width=600, anchor="w", minwidth=300, stretch=False)
        tree.column("File Name", width=350, anchor="w", minwidth=200, stretch=False)
        tree.column("Selected", width=60, anchor="center", minwidth=60, stretch=False)
        
        # Pack scrollbars và tree
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        
        # Bind double-click
        tree.bind("<Double-1>", lambda e, cat=category_key, t=tree: self.toggle_checkbox(cat, t))
        
        # Thêm border cho mỗi row
        tree.tag_configure("row", background="#FFFFFF")
        
        self.tables[category_key] = tree
        
        return tree
        
    def toggle_checkbox(self, category_key, tree):
        """Toggle checkbox khi double-click: sử dụng item's iid (lưu full_path)"""
        sel = tree.selection()
        if not sel:
            return
        item_id = sel[0]  # we store full_path as iid
        full_path = item_id
        # Tìm var trong checkboxes
        var = None
        if category_key in self.checkboxes:
            var = self.checkboxes[category_key].get(full_path)
        if var is None:
            return
        # Toggle
        new_val = 0 if var.get() == 1 else 1
        var.set(new_val)
        # Cập nhật hiển thị trong tree (nếu item đang hiển thị)
        try:
            vals = list(tree.item(item_id, "values"))
            vals[3] = "☑" if new_val == 1 else "☐"
            tree.item(item_id, values=vals)
        except Exception:
            pass
        
    def clear_search(self):
        """Xóa search box"""
        self.search_var.set("")
        
    def filter_tables(self):
        """Lọc bảng theo từ khóa search - case-insensitive, tìm trong file name và folder path và full_path"""
        search_term = self.search_var.get().lower().strip()
        
        for category_key, tree in self.tables.items():
            # Xóa tất cả items hiện tại
            for item in tree.get_children():
                tree.delete(item)
            
            # Lấy dữ liệu gốc
            if category_key not in self.all_data:
                continue
            
            # Lọc và hiển thị lại (tìm trong file_name, folder_path, full_path)
            for stt, folder_path, file_name, var, full_path in self.all_data[category_key]:
                folder_lower = folder_path.lower()
                file_lower = file_name.lower()
                full_lower = full_path.lower()
                
                show = False
                if not search_term:
                    show = True
                else:
                    if search_term in file_lower or search_term in folder_lower or search_term in full_lower:
                        show = True
                
                if show:
                    checkbox_state = "☑" if var.get() == 1 else "☐"
                    # use full_path as iid to map back easily
                    try:
                        tree.insert("", "end", iid=full_path, values=(stt, folder_path, file_name, checkbox_state), tags=("row",))
                    except Exception:
                        # If iid invalid or duplicates, insert without iid
                        tree.insert("", "end", values=(stt, folder_path, file_name, checkbox_state), tags=("row",))
    
    def select_section(self, category_key):
        """Chọn tất cả trong section - cập nhật var và hiển thị visible items"""
        tree = self.tables.get(category_key)
        if tree:
            # Cập nhật tất cả var (kể cả item không hiển thị trong filter)
            if category_key in self.checkboxes:
                for var in self.checkboxes[category_key].values():
                    var.set(1)
            # Cập nhật hiển thị trong table hiện tại
            for item in tree.get_children():
                values = list(tree.item(item, "values"))
                values[3] = "☑"
                tree.item(item, values=values)
                
    def deselect_section(self, category_key):
        """Bỏ chọn tất cả trong section"""
        tree = self.tables.get(category_key)
        if tree:
            if category_key in self.checkboxes:
                for var in self.checkboxes[category_key].values():
                    var.set(0)
            for item in tree.get_children():
                values = list(tree.item(item, "values"))
                values[3] = "☐"
                tree.item(item, values=values)
        
    def clear_content(self):
        """Xóa nội dung content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
            
    def show_spinner(self):
        """Hiển thị spinner"""
        self.results_outer_frame.pack_forget()
        self.spinner_frame.pack(fill="both", expand=True)
        self.progress.start(10)
        self.refresh_btn.config(state="disabled")
        
    def hide_spinner(self):
        """Ẩn spinner"""
        self.progress.stop()
        self.spinner_frame.pack_forget()
        self.results_outer_frame.pack(fill="both", expand=True)
        self.refresh_btn.config(state="normal")
        
    def refresh_scan(self):
        """Refresh - quét lại file .avc
           Yêu cầu: khi Refresh -> Search box tự động xóa
        """
        # Clear search box to satisfy requirement
        self.search_var.set("")
        # Xóa dữ liệu cũ hiển thị
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.checkboxes = {}
        self.tables = {}
        self.all_data = {}
        self.file_info_label.config(text="")
        self.current_avc_file = None
        
        # Quét lại
        self.scan_avc_files()
        
    def scan_avc_files(self):
        """Quét file .avc trong thread riêng"""
        self.show_spinner()
        
        def scan_thread():
            try:
                # Tìm file .avc
                current_dir = self.get_base_dir()
                avc_files = list(current_dir.glob("*.avc"))
                
                if not avc_files:
                    self.root.after(0, lambda: self.display_error("❌ Không tìm thấy file .avc nào trong thư mục hiện tại!"))
                    return
                
                # Nếu có nhiều file, chọn file đầu tiên hoặc cho user chọn
                if len(avc_files) > 1:
                    self.root.after(0, lambda: self.show_file_selection(avc_files))
                else:
                    self.process_avc_file(avc_files[0])
                    
            except Exception as e:
                self.root.after(0, lambda: self.display_error(f"❌ Lỗi: {str(e)}"))
                
        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()
        
    def show_file_selection(self, avc_files):
        """Hiển thị dialog chọn file"""
        self.hide_spinner()
        
        # Xóa bảng cũ
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.checkboxes = {}
        self.tables = {}
        self.file_info_label.config(text="")
        
        selection_window = tk.Toplevel(self.root)
        selection_window.title("Chọn file .avc")
        selection_window.geometry("500x400")
        selection_window.configure(bg="white")
        selection_window.transient(self.root)
        selection_window.grab_set()
        
        tk.Label(
            selection_window,
            text=f"📂 Tìm thấy {len(avc_files)} file .avc:",
            bg="white",
            font=("Segoe UI", 12, "bold")
        ).pack(pady=15)
        
        listbox_frame = tk.Frame(selection_window, bg="white")
        listbox_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side="right", fill="y")
        
        listbox = tk.Listbox(
            listbox_frame,
            font=("Segoe UI", 10),
            yscrollcommand=scrollbar.set,
            relief="solid",
            borderwidth=1
        )
        listbox.pack(fill="both", expand=True)
        scrollbar.config(command=listbox.yview)
        
        for f in avc_files:
            listbox.insert(tk.END, f.name)
            
        def on_select():
            selection = listbox.curselection()
            if selection:
                selected_file = avc_files[selection[0]]
                selection_window.destroy()
                
                # Xóa bảng và hiển thị spinner
                for widget in self.results_frame.winfo_children():
                    widget.destroy()
                self.checkboxes = {}
                self.tables = {}
                
                self.show_spinner()
                threading.Thread(
                    target=lambda: self.process_avc_file(selected_file),
                    daemon=True
                ).start()
            else:
                messagebox.showwarning("Cảnh báo", "Vui lòng chọn một file!")
                
        tk.Button(
            selection_window,
            text="Chọn",
            command=on_select,
            bg="#3498db",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            cursor="hand2",
            padx=20,
            pady=10
        ).pack(pady=15)
        
    def process_avc_file(self, avc_file):
        """Xử lý file .avc"""
        try:
            self.current_avc_file = avc_file
            
            # Tạo backup
            backup_name = f"temp_{avc_file.stem}.avc"
            backup_path = avc_file.parent / backup_name
            shutil.copy2(avc_file, backup_path)
            
            # Extract paths
            paths = self.extract_paths_from_avc(backup_path)
            
            # Xóa backup
            backup_path.unlink()
            
            if paths:
                self.root.after(0, lambda: self.display_results(paths, avc_file.name))
            else:
                self.root.after(0, lambda: self.display_error("❌ Không tìm thấy đường dẫn nào trong file .avc"))
                
        except Exception as e:
            self.root.after(0, lambda: self.display_error(f"❌ Lỗi khi xử lý file: {str(e)}"))
            
    def extract_paths_from_avc(self, avc_file):
        """Trích xuất đường dẫn từ file .avc"""
        paths = {
            'video_clips': set(),
            'audio_clips': set(),
            'images': set(),
            'effects': set(),
            'other': set()
        }
        
        audio_priority_set = set()
        
        try:
            tree = ET.parse(avc_file)
            root = tree.getroot()
            
            for elem in root.iter():
                elem_name = elem.tag.lower()
                is_audio_source = 'audio' in elem_name
                
                for attr_name, attr_value in elem.attrib.items():
                    attr_lower = attr_name.lower()
                    
                    if attr_lower not in ['filename', 'path', 'source', 'filepath', 'url']:
                        continue
                    
                    if not attr_value:
                        continue
                    
                    if not (('\\' in attr_value or '/' in attr_value) or 
                            attr_value.lower().endswith((
                                '.mov','.mp4','.avi','.wav','.mp3','.aiff',
                                '.jpg','.png','.gif','.bmp'
                            ))):
                        continue
                    
                    ext = os.path.splitext(attr_value)[1].lower()
                    
                    # Audio có độ ưu tiên cao nhất
                    if is_audio_source or ext in ['.wav', '.mp3', '.aiff', '.aif', '.ogg', '.flac', '.m4a']:
                        paths['audio_clips'].add(attr_value)
                        audio_priority_set.add(attr_value)
                        continue
                    
                    if attr_value in audio_priority_set:
                        continue
                    
                    if ext in ['.mov', '.mp4', '.avi', '.webm', '.mkv', '.flv', '.wmv']:
                        paths['video_clips'].add(attr_value)
                    elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tga', '.webp']:
                        paths['images'].add(attr_value)
                    elif ext in ['.dll', '.plugin', '.vst', '.vst3', '.component']:
                        paths['effects'].add(attr_value)
                    else:
                        paths['other'].add(attr_value)
            
            for key in paths:
                paths[key] = sorted(paths[key])
            
            return paths
            
        except Exception as e:
            print(f"Error parsing XML: {e}")
            return None
            
    def display_results(self, paths, filename):
        """Hiển thị kết quả trong các bảng riêng biệt"""
        self.hide_spinner()
        
        # Xóa dữ liệu cũ
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        # init checkboxes as dict mapping full_path -> IntVar
        self.checkboxes = {
            'video': {},
            'audio': {},
            'image': {},
            'effect': {},
            'other': {}
        }
        self.tables = {}
        self.all_data = {}
        
        # File info
        total = sum(len(v) for v in paths.values())
        self.file_info_label.config(text=f"📄 File: {filename} | Tổng: {total} files")
        
        # Tạo bảng cho từng loại
        sections = [
            ('video', '🎬 VIDEO CLIPS', paths['video_clips']),
            ('audio', '🎵 AUDIO CLIPS', paths['audio_clips']),
            ('image', '🖼️ IMAGES', paths['images']),
            ('effect', '✨ EFFECTS/PLUGINS', paths['effects']),
            ('other', '📁 OTHER FILES', paths['other'])
        ]
        
        for category_key, title, file_list in sections:
            if len(file_list) > 0:
                tree = self.create_section_table(
                    self.results_frame,
                    title,
                    title.split()[0],
                    category_key,
                    len(file_list)
                )
                
                # THAY ĐỔI: Thêm dữ liệu vào bảng với checkbox mặc định là ☐ (None)
                self.all_data[category_key] = []
                for i, full_path in enumerate(file_list, 1):
                    path_obj = Path(full_path)
                    folder_path = str(path_obj.parent).replace("\\", "/") + "/"
                    file_name = path_obj.name
                    
                    # Tạo checkbox variable với giá trị mặc định là 0
                    var = tk.IntVar(value=0)
                    # store var in dict for quick lookup
                    self.checkboxes[category_key][full_path] = var
                    
                    # lưu vào all_data để filter dựa trên source gốc
                    self.all_data[category_key].append((i, folder_path, file_name, var, full_path))
                    
                    # Insert vào table với checkbox ☐ (hiển thị ban đầu là tất cả)
                    tree.insert("", "end", iid=full_path, values=(i, folder_path, file_name, "☐"), tags=("row",))
        
        if total == 0:
            tk.Label(
                self.results_frame,
                text="⚠️ Không tìm thấy đường dẫn file nào trong .avc",
                bg="white",
                fg="#DC3545",
                font=("Segoe UI", 12, "bold")
            ).pack(pady=50)
        
    def display_error(self, message):
        """Hiển thị lỗi"""
        self.hide_spinner()
        messagebox.showerror("Lỗi", message)
        
    def run(self):
        """Chạy ứng dụng"""
        self.root.mainloop()

def main():
    app = AVCExtractorGUI()
    app.run()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        messagebox.showerror("Lỗi", f"Đã xảy ra lỗi: {str(e)}")
        sys.exit(1)
