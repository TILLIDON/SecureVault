import qrcode
from PIL import Image
import os
import json
import platform
import secrets
import threading
import time
import customtkinter as ctk

from tkinter import filedialog, messagebox

from cloud.supabase_client import SecureVaultCloud

from encryption.file_encryption import (
    encrypt_file,
    decrypt_file,
    encrypt_folder,
    decrypt_folder
)


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class SecureVaultApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("SecureVault")
        self.geometry("1180x780")
        self.resizable(True, True)
        self.configure(fg_color="#0B1120")

        self.cloud = SecureVaultCloud()

        self.vault_key = None
        self.current_email = None

        self.pending_email = None
        self.pending_password = None
        self.pending_action = None
        self.pending_email_change = None

        self.operation_running = False
        self.reauth_code_sent = False

        self.totp_factor_id = None
        self.totp_challenge_id = None
        self.totp_secret = None
        self.removal_factor_id = None
        self.removal_challenge_id = None

        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        self.project_root = project_root
        self.settings_file = os.path.join(
            project_root,
            ".securevault_settings.json"
        )
        self.app_preferences = self.load_app_preferences()
        self.appearance_mode = self.app_preferences.get(
            "appearance",
            "dark"
        )
        self.accent_theme = self.app_preferences.get("accent_theme", "blue")
        ctk.set_default_color_theme(self.accent_theme)
        ctk.set_appearance_mode(self.appearance_mode)

        # Activity tracking is used only while a vault key is loaded.
        self.last_activity_at = time.monotonic()
        self.bind_all("<KeyPress>", self._record_user_activity, add="+")
        self.bind_all("<ButtonPress>", self._record_user_activity, add="+")
        self.bind_all("<Motion>", self._record_user_activity, add="+")

        self.first_encryption_flag = os.path.join(
            project_root,
            ".securevault_first_encryption_done"
        )

        self.first_encryption_shown = os.path.exists(
            self.first_encryption_flag
        )

        self.feedback_flag = os.path.join(
            project_root,
            ".securevault_feedback_completed"
        )

        self.feedback_completed = os.path.exists(
            self.feedback_flag
        )

        self.selected_feedback_rating = 5

        self.show_login_screen()
        self.after(5000, self._check_auto_lock)

    # ==================================================
    # GENERAL UI
    # ==================================================

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    def create_title(self, title, subtitle=""):
        wrap = ctk.CTkFrame(self, fg_color="transparent")
        wrap.pack(fill="x", padx=36, pady=(42, 22))
        ctk.CTkLabel(wrap, text=title.upper(), font=("Segoe UI", 27, "bold"),
                     text_color="#F1F5F9").pack(anchor="center", pady=(0, 8))
        if subtitle:
            ctk.CTkLabel(wrap, text=subtitle, font=("Segoe UI", 13),
                         text_color="#9FB0C5", wraplength=760,
                         justify="center").pack(anchor="center")

    def create_entry(self, placeholder, show=None):
        entry = ctk.CTkEntry(
            self, width=390, height=48, placeholder_text=placeholder, show=show,
            font=("Segoe UI", 14), corner_radius=10, border_width=1,
            border_color="#2A405A", fg_color="#111C2E",
            text_color="#F1F5F9", placeholder_text_color="#71839B"
        )
        entry.pack(pady=9)
        return entry

    def show_error(self, error):
        messagebox.showerror("SecureVault", str(error))

    def show_success(self, message):
        messagebox.showinfo("SecureVault", message)

    def create_button(self, text, command, width=390, height=46,
                      fg_color="#0891B2", hover_color="#0E7490"):
        button = ctk.CTkButton(
            self, text=text, width=width, height=height,
            fg_color=fg_color, hover_color=hover_color,
            text_color="#F8FAFC", font=("Segoe UI", 13, "bold"),
            corner_radius=10, command=command
        )
        button.pack(pady=8)
        return button

    # ==================================================
    # LOGIN
    # ==================================================

    def show_login_screen(self):

        self.clear_screen()

        self.create_title(
            "SECUREVAULT",
            "Secure access to your encrypted files"
        )

        self.email_entry = self.create_entry("Email address")
        self.password_entry = self.create_entry(
            "Password",
            show="*"
        )

        self.create_button(
            "LOGIN",
            self.login_user
        )

        ctk.CTkButton(
            self,
            text="Create New Account",
            width=350,
            height=40,
            fg_color="transparent",
            border_width=1,
            command=self.show_register_screen
        ).pack(pady=8)

        ctk.CTkButton(
            self,
            text="Forgot Password?",
            width=350,
            height=35,
            fg_color="transparent",
            hover=False,
            command=self.show_recovery_screen
        ).pack(pady=5)

    def login_user(self):
        email = self.email_entry.get().strip().lower()
        password = self.password_entry.get()
        if not email or not password:
            self.show_error("Please enter your email and password.")
            return

        try:
            self.cloud.login(email, password)
            self.password_entry.delete(0, "end")
            password = None

            try:
                restored_vmk = self.cloud.retrieve_vmk()
            except Exception as recovery_error:
                # Only this explicit server response starts the first-device OTP flow.
                if getattr(recovery_error, "code", None) != "DEVICE_VERIFICATION_REQUIRED":
                    raise
                self.cloud.send_login_otp(email)
                self.pending_email = email
                self.pending_action = "trusted_device"
                self.show_otp_screen(
                    "TRUST THIS DEVICE",
                    "This device is not trusted yet. Enter the email OTP to register it securely."
                )
                return

            if not restored_vmk or len(restored_vmk) != 32:
                raise Exception("Your vault key could not be restored. Do not create a new vault or modify encrypted files.")

            self.vault_key = restored_vmk
            self.current_email = email
            self.pending_email = None
            self.pending_password = None
            self.pending_action = None
            self.last_activity_at = time.monotonic()
            self.show_dashboard()

        except Exception as error:
            self.vault_key = None
            self.current_email = None
            try:
                self.cloud.logout()
            except Exception:
                pass
            self.show_error(error)

    # ==================================================
    # REGISTRATION
    # ==================================================

    def show_register_screen(self):

        self.clear_screen()

        self.create_title(
            "CREATE ACCOUNT",
            "Register using your email address"
        )

        self.register_email = self.create_entry("Email address")
        self.register_password = self.create_entry(
            "Create password",
            show="*"
        )
        self.confirm_password = self.create_entry(
            "Confirm password",
            show="*"
        )

        self.create_button(
            "REGISTER",
            self.register_user
        )

        ctk.CTkButton(
            self,
            text="Back to Login",
            width=350,
            fg_color="transparent",
            command=self.show_login_screen
        ).pack(pady=8)

    def register_user(self):

        email = self.register_email.get().strip().lower()
        password = self.register_password.get()
        confirm = self.confirm_password.get()

        if not email or not password or not confirm:
            self.show_error("Please fill in all fields.")
            return

        if password != confirm:
            self.show_error("Passwords do not match.")
            return

        if len(password) < 8:
            self.show_error(
                "Password must contain at least 8 characters."
            )
            return

        try:
            self.cloud.register(email, password)

            # Clear both password fields as soon as registration is accepted.
            self.register_password.delete(0, "end")
            self.confirm_password.delete(0, "end")
            password = None
            confirm = None

            self.pending_email = email
            self.pending_password = None
            self.pending_action = "register"

            self.show_otp_screen(
                "Verify Your Email",
                "Enter the verification OTP sent to your email."
            )

        except Exception as e:
            self.show_error(e)

    # ==================================================
    # OTP
    # ==================================================

    def show_otp_screen(self, title, subtitle):

        self.clear_screen()

        self.create_title(title, subtitle)

        ctk.CTkLabel(
            self,
            text=self.pending_email or "",
            font=("Segoe UI", 14),
            text_color="#22D3EE"
        ).pack(pady=5)

        self.otp_entry = self.create_entry("Enter 6-digit OTP")

        self.create_button(
            "VERIFY OTP",
            self.verify_otp
        )

        ctk.CTkButton(
            self,
            text="Back to Login",
            width=350,
            fg_color="transparent",
            command=self.show_login_screen
        ).pack(pady=8)

    def verify_otp(self):

        otp = self.otp_entry.get().strip()

        if not otp:
            self.show_error("Please enter the OTP.")
            return

        if not otp.isdigit() or len(otp) != 6:
            self.show_error(
                "Please enter a valid 6-digit OTP."
            )
            return

        try:

            if self.pending_action == "register":

                self.cloud.verify_email(
                    self.pending_email,
                    otp
                )

                new_vmk = secrets.token_bytes(32)
                self.cloud.backup_vmk(new_vmk)

                # The successful signup OTP is fresh verification, so this
                # Windows profile can be enrolled as the first trusted device.
                device_trust_note = ""
                try:
                    self.cloud.register_trusted_device()
                except Exception:
                    # Account creation and VMK backup remain successful; the
                    # next password login will simply ask for a device OTP.
                    device_trust_note = "\nThis device could not be remembered, so its first login will require OTP."

                self.vault_key = new_vmk
                self.current_email = self.pending_email

                self.pending_email = None
                self.pending_action = None

                self.show_success(
                    "Registration successful!\n"
                    "Your vault key has been securely backed up."
                    + device_trust_note
                )

                self.show_dashboard()

            elif self.pending_action == "trusted_device":

                # OTP verification upgrades this session, then enrolls this
                # Windows user profile as a trusted device using DPAPI storage.
                self.cloud.verify_login_otp(self.pending_email, otp)
                self.cloud.register_trusted_device()
                restored_vmk = self.cloud.retrieve_vmk()
                if not restored_vmk or len(restored_vmk) != 32:
                    raise Exception("Device was verified, but the existing vault key could not be restored.")

                self.vault_key = restored_vmk
                self.current_email = self.pending_email
                self.pending_email = None
                self.pending_action = None
                self.last_activity_at = time.monotonic()
                self.show_success("This Windows device is now trusted. Future logins on this Windows user account will not require a login OTP.")
                self.show_dashboard()

            elif self.pending_action == "revoke_device":

                self.cloud.verify_login_otp(self.pending_email, otp)
                self.cloud.revoke_this_device()
                self.pending_email = None
                self.pending_action = None
                self.show_success("Trust has been revoked. This device will need email OTP next time it signs in.")
                self.show_devices_settings()

            elif self.pending_action == "recovery":

                self.cloud.verify_recovery_otp(
                    self.pending_email,
                    otp
                )

                self.show_reset_password_screen()

            elif self.pending_action == "email_change":

                result = self.cloud._request(
                    "/auth/v1/verify",
                    data={
                        "email": self.pending_email_change,
                        "token": otp,
                        "type": "email_change"
                    }
                )

                self.cloud._set_session(result)

                self.current_email = self.pending_email_change
                self.pending_email_change = None
                self.pending_action = None
                self.pending_email = None

                self.show_success(
                    "Your email address has been updated successfully."
                )

                self.show_account_settings()

        except Exception as e:
            self.show_error(e)

    # ==================================================
    # PASSWORD RECOVERY
    # ==================================================

    def show_recovery_screen(self):

        self.clear_screen()

        self.create_title(
            "ACCOUNT RECOVERY",
            "Recover your account using email verification"
        )

        self.recovery_email = self.create_entry(
            "Registered email address"
        )

        self.create_button(
            "SEND RECOVERY OTP",
            self.send_recovery_otp
        )

        ctk.CTkButton(
            self,
            text="Back to Login",
            width=350,
            fg_color="transparent",
            command=self.show_login_screen
        ).pack(pady=8)

    def send_recovery_otp(self):

        email = self.recovery_email.get().strip().lower()

        if not email:
            self.show_error(
                "Please enter your registered email."
            )
            return

        try:
            self.cloud.send_recovery_otp(email)

            self.pending_email = email
            self.pending_action = "recovery"

            self.show_otp_screen(
                "Recovery Verification",
                "Enter the recovery OTP sent to your email."
            )

        except Exception as e:
            self.show_error(e)

    def show_reset_password_screen(self):

        self.clear_screen()

        self.create_title(
            "RESET PASSWORD",
            "Create a new password for your account"
        )

        self.new_password_entry = self.create_entry(
            "New password",
            show="*"
        )

        self.confirm_new_password_entry = self.create_entry(
            "Confirm new password",
            show="*"
        )

        self.create_button(
            "RESET PASSWORD",
            self.reset_password
        )

    def reset_password(self):

        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_new_password_entry.get()

        if not new_password or not confirm_password:
            self.show_error("Please fill in both password fields.")
            return

        if new_password != confirm_password:
            self.show_error("Passwords do not match.")
            return

        if len(new_password) < 8:
            self.show_error(
                "Password must contain at least 8 characters."
            )
            return

        try:
            self.cloud.update_password(new_password)

            # The new password is no longer needed after the update request.
            self.new_password_entry.delete(0, "end")
            self.confirm_new_password_entry.delete(0, "end")
            new_password = None
            confirm_password = None

            self.vault_key = self.cloud.retrieve_vmk()

            if not self.vault_key or len(self.vault_key) != 32:
                raise Exception(
                    "Could not retrieve your existing vault key."
                )

            self.current_email = self.pending_email
            self.pending_email = None
            self.pending_action = None

            self.show_success("Password changed successfully!")
            self.show_dashboard()

        except Exception as e:
            self.show_error(e)

    # ==================================================
    # DASHBOARD
    # ==================================================

    def show_dashboard(self):
        self.last_activity_at = time.monotonic()
        self.clear_screen()
        self.configure(fg_color="#0B1120")

        shell = ctk.CTkFrame(self, fg_color="transparent")
        shell.pack(fill="both", expand=True)

        sidebar = ctk.CTkFrame(shell, width=224, corner_radius=0, fg_color="#0D1728")
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=22, pady=(28, 34))
        ctk.CTkLabel(brand, text="◈", font=("Segoe UI Symbol", 30, "bold"),
                     text_color="#22D3EE").pack(side="left", padx=(0, 10))
        ctk.CTkLabel(brand, text="SecureVault", font=("Segoe UI", 19, "bold"),
                     text_color="#F8FAFC").pack(side="left")

        ctk.CTkLabel(sidebar, text="WORKSPACE", font=("Segoe UI", 10, "bold"),
                     text_color="#647A96").pack(anchor="w", padx=24, pady=(0, 10))
        ctk.CTkButton(
            sidebar, text="▦   Overview", anchor="w", height=42,
            fg_color="#123449", hover_color="#16465D", text_color="#67E8F9",
            font=("Segoe UI", 13, "bold"), corner_radius=9,
            command=self.show_dashboard
        ).pack(fill="x", padx=14, pady=4)
        ctk.CTkButton(
            sidebar, text="⚙   Account settings", anchor="w", height=42,
            fg_color="transparent", hover_color="#1B2A40", text_color="#A9B8CC",
            font=("Segoe UI", 13), corner_radius=9,
            command=self.show_account_settings
        ).pack(fill="x", padx=14, pady=4)

        ctk.CTkFrame(sidebar, fg_color="#24364D", height=1).pack(fill="x", padx=20, pady=22)
        ctk.CTkLabel(sidebar, text="PROTECTION STATUS", font=("Segoe UI", 10, "bold"),
                     text_color="#647A96").pack(anchor="w", padx=24, pady=(0, 12))
        ctk.CTkLabel(sidebar, text="●  Vault unlocked", font=("Segoe UI", 12, "bold"),
                     text_color="#4ADE80").pack(anchor="w", padx=24, pady=4)
        ctk.CTkLabel(sidebar, text="AES-256-GCM", font=("Segoe UI", 11),
                     text_color="#8FA3BC").pack(anchor="w", padx=42)
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(fill="both", expand=True)
        ctk.CTkLabel(sidebar, text=(self.current_email or ""), font=("Segoe UI", 10),
                     text_color="#71839B", wraplength=180).pack(anchor="w", padx=20, pady=(8, 12))
        ctk.CTkButton(
            sidebar, text="Sign out", height=40, fg_color="#3A2533",
            hover_color="#5B2D3D", text_color="#FCA5A5",
            font=("Segoe UI", 12, "bold"), corner_radius=9, command=self.logout
        ).pack(fill="x", padx=14, pady=(0, 22))

        content = ctk.CTkFrame(shell, fg_color="transparent")
        content.pack(side="left", fill="both", expand=True, padx=34, pady=28)
        top = ctk.CTkFrame(content, fg_color="transparent")
        top.pack(fill="x", pady=(0, 24))
        greeting = ctk.CTkFrame(top, fg_color="transparent")
        greeting.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(greeting, text="SECURE WORKSPACE", font=("Segoe UI", 10, "bold"),
                     text_color="#22D3EE").pack(anchor="w")
        ctk.CTkLabel(greeting, text="Your files. Your control.",
                     font=("Segoe UI", 29, "bold"), text_color="#F8FAFC").pack(anchor="w", pady=(5, 2))
        ctk.CTkLabel(greeting,
                     text="Protect sensitive files and folders with authenticated encryption.",
                     font=("Segoe UI", 13), text_color="#91A4BC").pack(anchor="w")
        ctk.CTkButton(
            top, text="⚙", width=46, height=44, fg_color="#17263A",
            hover_color="#23415A", text_color="#67E8F9", font=("Segoe UI", 20),
            corner_radius=10, command=self.show_account_settings
        ).pack(side="right", padx=(10, 0))

        hero = ctk.CTkFrame(content, fg_color="#10283A", corner_radius=18,
                            border_width=1, border_color="#15506A")
        hero.pack(fill="x", pady=(0, 22))
        hero_inner = ctk.CTkFrame(hero, fg_color="transparent")
        hero_inner.pack(fill="x", padx=24, pady=20)
        ctk.CTkLabel(hero_inner, text="◈  VAULT PROTECTION ACTIVE",
                     font=("Segoe UI", 11, "bold"), text_color="#67E8F9").pack(anchor="w")
        ctk.CTkLabel(hero_inner,
                     text="AES-256-GCM  •  Encrypted locally  •  Protected by your vault key",
                     font=("Segoe UI", 13), text_color="#D3E5F2").pack(anchor="w", pady=(8, 0))

        ctk.CTkLabel(content, text="FILE PROTECTION", font=("Segoe UI", 11, "bold"),
                     text_color="#7188A4").pack(anchor="w", pady=(2, 12))
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(fill="x")
        cards = [
            ("01", "Encrypt a file", "Secure an individual file", self.encrypt_file_action, "#0891B2"),
            ("02", "Decrypt a file", "Restore a protected file", self.decrypt_file_action, "#1D4E70"),
            ("03", "Encrypt a folder", "Protect a complete folder", self.encrypt_folder_action, "#1D4E70"),
            ("04", "Decrypt a folder", "Restore a protected folder", self.decrypt_folder_action, "#1D4E70"),
        ]
        for index, (number, title, desc, command, accent) in enumerate(cards):
            card = ctk.CTkFrame(actions, fg_color="#111C2E", corner_radius=14,
                                border_width=1, border_color="#24364D", height=136)
            card.grid(row=index // 2, column=index % 2, padx=7, pady=7, sticky="nsew")
            card.grid_propagate(False)
            ctk.CTkLabel(card, text=number, font=("Segoe UI", 11, "bold"),
                         text_color="#22D3EE").pack(anchor="w", padx=17, pady=(13, 2))
            ctk.CTkLabel(card, text=title, font=("Segoe UI", 16, "bold"),
                         text_color="#F1F5F9").pack(anchor="w", padx=17, pady=(2, 1))
            ctk.CTkLabel(card, text=desc, font=("Segoe UI", 11),
                         text_color="#91A4BC").pack(anchor="w", padx=17)
            ctk.CTkButton(
                card, text="Open  →", width=112, height=30, fg_color=accent,
                hover_color="#0E7490", font=("Segoe UI", 11, "bold"),
                corner_radius=8, command=command
            ).pack(anchor="e", padx=14, pady=(5, 10))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=1)

        activity = ctk.CTkFrame(content, fg_color="#111C2E", corner_radius=14,
                                 border_width=1, border_color="#24364D")
        activity.pack(fill="x", pady=(17, 0))
        ctk.CTkLabel(activity, text="OPERATION STATUS", font=("Segoe UI", 10, "bold"),
                     text_color="#7188A4").pack(anchor="w", padx=18, pady=(13, 3))
        self.progress_label = ctk.CTkLabel(activity, text="Ready when you are",
                                           font=("Segoe UI", 12), text_color="#D7E3F0")
        self.progress_label.pack(anchor="w", padx=18, pady=(0, 5))
        self.progress_bar = ctk.CTkProgressBar(
            activity, height=8, progress_color="#22D3EE",
            fg_color="#263B52", corner_radius=8
        )
        self.progress_bar.pack(fill="x", padx=18, pady=(0, 15))
        self.progress_bar.set(0)
        ctk.CTkLabel(
            content, text="Your vault key remains in memory only while this session is unlocked.",
            font=("Segoe UI", 10), text_color="#647A96"
        ).pack(anchor="w", pady=(12, 0))


    # ==================================================
    # SETTINGS HUB AND PREFERENCES
    # ==================================================

    def load_app_preferences(self):
        defaults = {
            "appearance": "dark",
            "accent_theme": "blue",
            "auto_lock_minutes": 10,
            "success_popups": True,
        }
        try:
            with open(self.settings_file, "r", encoding="utf-8") as file:
                data = json.load(file)
            if not isinstance(data, dict):
                return defaults
            prefs = dict(defaults)
            prefs.update(data)
            if str(prefs.get("appearance", "dark")).lower() not in (
                "dark", "light", "system"
            ):
                prefs["appearance"] = "dark"
            if prefs.get("accent_theme") not in ("blue", "green", "dark-blue"):
                prefs["accent_theme"] = "blue"
            try:
                prefs["auto_lock_minutes"] = int(prefs["auto_lock_minutes"])
            except (TypeError, ValueError):
                prefs["auto_lock_minutes"] = 10
            if prefs["auto_lock_minutes"] not in (0, 5, 10, 15, 30):
                prefs["auto_lock_minutes"] = 10
            prefs["success_popups"] = bool(prefs.get("success_popups", True))
            return prefs
        except (OSError, json.JSONDecodeError, AttributeError):
            return defaults

    def save_app_preferences(self):
        try:
            temporary_file = self.settings_file + ".tmp"
            with open(temporary_file, "w", encoding="utf-8") as file:
                json.dump(self.app_preferences, file, indent=4)
            os.replace(temporary_file, self.settings_file)
        except OSError as error:
            self.show_error(
                "Could not save your SecureVault preferences:\n"
                f"{error}"
            )

    def _record_user_activity(self, _event=None):
        self.last_activity_at = time.monotonic()

    def _check_auto_lock(self):
        try:
            if self.vault_key and self.current_email:
                timeout = int(self.app_preferences.get("auto_lock_minutes", 10))
                if timeout > 0:
                    elapsed = time.monotonic() - self.last_activity_at
                    if elapsed >= timeout * 60 and not self.operation_running:
                        self.logout(reason="SecureVault locked after inactivity.")
                        try:
                            self.after(5000, self._check_auto_lock)
                        except Exception:
                            pass
                        return
        except (AttributeError, TypeError, ValueError):
            pass
        try:
            if self.winfo_exists():
                self.after(5000, self._check_auto_lock)
        except Exception:
            pass

    def change_auto_lock_setting(self, selected):
        values = {
            "Off": 0,
            "5 minutes": 5,
            "10 minutes": 10,
            "15 minutes": 15,
            "30 minutes": 30,
        }
        if selected not in values:
            return
        self.app_preferences["auto_lock_minutes"] = values[selected]
        self.last_activity_at = time.monotonic()
        self.save_app_preferences()

    def change_accent_theme(self, selected):
        themes = {
            "Cyan": "blue",
            "Blue": "blue",
            "Green": "green",
            "Dark blue": "dark-blue",
        }
        theme = themes.get(selected)
        if not theme:
            return
        self.accent_theme = theme
        self.app_preferences["accent_theme"] = theme
        ctk.set_default_color_theme(theme)
        self.save_app_preferences()
        self.show_appearance_settings()

    def change_success_popup_preference(self, enabled):
        self.app_preferences["success_popups"] = bool(enabled)
        self.save_app_preferences()

    def backup_vault_key_now(self):
        if not self.vault_key or len(self.vault_key) != 32:
            self.show_error("Your vault is locked. Sign in again before creating a backup.")
            return
        try:
            self.cloud.backup_vmk(self.vault_key)
            self.show_success(
                "Vault-key backup request completed successfully.\n\n"
                "This confirms the cloud backup service accepted the request; "
                "it is not an independent restore or integrity test."
            )
        except Exception as error:
            self.show_error(
                "SecureVault could not update the cloud vault-key backup.\n\n"
                f"{error}\n\n"
                "If the service requires recent verification, complete the "
                "sign-in verification flow and try again."
            )

    def _settings_page_header(self, title, subtitle):
        self.clear_screen()

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=30, pady=(22, 5))

        ctk.CTkButton(
            top,
            text="←  Settings",
            width=115,
            height=34,
            fg_color="#1B2A40",
            hover_color="#29445F",
            command=self.show_account_settings
        ).pack(side="left")

        ctk.CTkLabel(
            self,
            text=title,
            font=("Segoe UI", 25, "bold"),
            text_color="#FFFFFF"
        ).pack(pady=(18, 6))

        ctk.CTkLabel(
            self,
            text=subtitle,
            font=("Segoe UI", 13),
            text_color="#A9B8CC",
            wraplength=700,
            justify="center"
        ).pack(pady=(0, 15))

    def _settings_info_card(self, parent, title, description,
                            status=None, status_color="#22D3EE"):
        card = ctk.CTkFrame(
            parent,
            fg_color="#111C2E",
            corner_radius=14,
            border_width=1,
            border_color="#24364D"
        )
        card.pack(fill="x", padx=45, pady=8)

        ctk.CTkLabel(
            card,
            text=title,
            font=("Segoe UI", 15, "bold"),
            text_color="#FFFFFF",
            anchor="w"
        ).pack(fill="x", padx=18, pady=(14, 5))

        ctk.CTkLabel(
            card,
            text=description,
            font=("Segoe UI", 12),
            text_color="#A9B8CC",
            wraplength=650,
            justify="left",
            anchor="w"
        ).pack(fill="x", padx=18, pady=(0, 8))

        if status:
            ctk.CTkLabel(
                card,
                text=status,
                font=("Segoe UI", 12, "bold"),
                text_color=status_color,
                anchor="w"
            ).pack(fill="x", padx=18, pady=(0, 13))
        else:
            ctk.CTkFrame(card, fg_color="transparent", height=5).pack()

        return card

    def show_account_settings(self):
        self.clear_screen()

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(24, 8))

        ctk.CTkButton(
            header,
            text="← Dashboard",
            width=125,
            height=36,
            fg_color="#1B2A40",
            hover_color="#29445F",
            command=self.show_dashboard
        ).pack(side="left")

        ctk.CTkLabel(
            header,
            text="SETTINGS",
            font=("Segoe UI", 27, "bold"),
            text_color="#FFFFFF"
        ).pack(side="right")

        ctk.CTkFrame(self, fg_color="transparent", height=3).pack()

        account_card = ctk.CTkFrame(
            self,
            fg_color="#13243A",
            corner_radius=16,
            border_width=1,
            border_color="#294767"
        )
        account_card.pack(fill="x", padx=32, pady=(12, 16))

        ctk.CTkLabel(
            account_card,
            text="SECUREVAULT ACCOUNT",
            font=("Segoe UI", 11, "bold"),
            text_color="#67E8F9"
        ).pack(anchor="w", padx=20, pady=(14, 4))

        ctk.CTkLabel(
            account_card,
            text=self.current_email or "No account signed in",
            font=("Segoe UI", 15, "bold"),
            text_color="#FFFFFF"
        ).pack(anchor="w", padx=20, pady=(0, 14))

        scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0
        )
        scroll.pack(fill="both", expand=True, padx=25, pady=(0, 12))

        sections = [
            (
                "Appearance",
                "Choose Dark, Light, or System appearance.",
                self.show_appearance_settings
            ),
            (
                "Security & Privacy",
                "Change your email, password, and authenticator settings.",
                self.show_security_settings
            ),
            (
                "Vault Settings",
                "View your vault protection and current session status.",
                self.show_vault_settings
            ),
            (
                "Backup & Recovery",
                "Learn how your encrypted vault key is backed up and recovered.",
                self.show_backup_settings
            ),
            (
                "Login & Devices",
                "View this device and manage your current login.",
                self.show_devices_settings
            ),
            (
                "Notifications",
                "Understand SecureVault operation and account notifications.",
                self.show_notification_settings
            ),
            (
                "About SecureVault",
                "View product information and security details.",
                self.show_about_settings
            )
        ]

        for index, (title, description, command) in enumerate(sections):
            card = ctk.CTkFrame(
                scroll,
                fg_color="#111C2E",
                corner_radius=14,
                border_width=1,
                border_color="#24364D",
                height=112
            )
            card.grid(
                row=index // 2,
                column=index % 2,
                padx=8,
                pady=8,
                sticky="nsew"
            )
            card.grid_propagate(False)

            ctk.CTkLabel(
                card,
                text=title,
                font=("Segoe UI", 15, "bold"),
                text_color="#FFFFFF",
                anchor="w"
            ).pack(fill="x", padx=15, pady=(13, 4))

            ctk.CTkLabel(
                card,
                text=description,
                font=("Segoe UI", 11),
                text_color="#A9B8CC",
                wraplength=310,
                justify="left",
                anchor="w"
            ).pack(fill="x", padx=15, pady=(0, 7))

            ctk.CTkButton(
                card,
                text="OPEN  →",
                width=105,
                height=28,
                font=("Segoe UI", 11, "bold"),
                fg_color="#0891B2",
                hover_color="#0E7490",
                command=command
            ).pack(anchor="e", padx=13, pady=(0, 9))

        scroll.grid_columnconfigure(0, weight=1)
        scroll.grid_columnconfigure(1, weight=1)

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=32, pady=(0, 12))

        ctk.CTkButton(
            footer,
            text="LOG OUT",
            width=130,
            height=36,
            fg_color="#8F3038",
            hover_color="#70242B",
            command=self.logout
        ).pack(side="right")

    def show_appearance_settings(self):
        self._settings_page_header(
            "APPEARANCE",
            "Personalize the SecureVault desktop experience."
        )

        card = ctk.CTkFrame(self, fg_color="#111C2E", corner_radius=14,
                            border_width=1, border_color="#24364D")
        card.pack(fill="x", padx=42, pady=10)
        ctk.CTkLabel(card, text="Display mode", font=("Segoe UI", 16, "bold"),
                     text_color="#FFFFFF").pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(card, text="Choose Dark, Light, or System appearance. Your choice is saved on this computer.",
                     font=("Segoe UI", 12), text_color="#A9B8CC", wraplength=650,
                     justify="left").pack(anchor="w", padx=18, pady=(0, 12))

        current = self.appearance_mode.title()
        mode_row = ctk.CTkFrame(card, fg_color="transparent")
        mode_row.pack(anchor="w", padx=12, pady=(0, 14))
        for mode in ("dark", "light", "system"):
            ctk.CTkButton(
                mode_row, text=mode.title(), width=120, height=36,
                fg_color="#0891B2" if self.appearance_mode == mode else "#1B2A40",
                hover_color="#0E7490",
                command=lambda selected=mode: self.change_appearance_setting(selected)
            ).pack(side="left", padx=6)

        accent_card = ctk.CTkFrame(self, fg_color="#111C2E", corner_radius=14,
                                   border_width=1, border_color="#24364D")
        accent_card.pack(fill="x", padx=42, pady=10)
        ctk.CTkLabel(accent_card, text="Accent colour", font=("Segoe UI", 16, "bold"),
                     text_color="#FFFFFF").pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(accent_card, text="Changes the default accent used by SecureVault controls and newly opened screens.",
                     font=("Segoe UI", 12), text_color="#A9B8CC", wraplength=650,
                     justify="left").pack(anchor="w", padx=18, pady=(0, 10))
        theme_names = {"blue": "Blue", "green": "Green", "dark-blue": "Dark blue"}
        accent_menu = ctk.CTkOptionMenu(
            accent_card, values=["Cyan", "Blue", "Green", "Dark blue"], width=180,
            command=self.change_accent_theme
        )
        accent_menu.set(theme_names.get(self.accent_theme, "Blue"))
        accent_menu.pack(anchor="w", padx=18, pady=(0, 16))

        ctk.CTkLabel(self, text="Preferences are stored locally in .securevault_settings.json.",
                     font=("Segoe UI", 11), text_color="#71839B").pack(pady=10)

    def change_appearance_setting(self, mode):
        if mode not in ("dark", "light", "system"):
            return
        self.appearance_mode = mode
        self.app_preferences["appearance"] = mode
        ctk.set_appearance_mode(mode)
        self.configure(fg_color="#0B1120" if mode != "light" else "#E9EEF5")
        self.save_app_preferences()
        self.show_appearance_settings()

    def show_security_settings(self):
        self._settings_page_header(
            "SECURITY & PRIVACY",
            "Manage your account credentials and session protection."
        )

        self._settings_info_card(
            self, "SecureVault account", self.current_email or "Not signed in"
        )

        credentials = ctk.CTkFrame(self, fg_color="#111C2E", corner_radius=14,
                                   border_width=1, border_color="#24364D")
        credentials.pack(fill="x", padx=42, pady=8)
        ctk.CTkLabel(credentials, text="Account credentials", font=("Segoe UI", 16, "bold"),
                     text_color="#FFFFFF").pack(anchor="w", padx=18, pady=(14, 8))
        for label, command in (
            ("Change email address", self.show_change_email_screen),
            ("Change password", self.show_change_password_screen),
            ("Authenticator management", self.show_authenticator_screen),
        ):
            ctk.CTkButton(credentials, text=label, height=38, anchor="w",
                          fg_color="#1B2A40", hover_color="#29445F",
                          command=command).pack(fill="x", padx=16, pady=5)
        ctk.CTkFrame(credentials, fg_color="transparent", height=8).pack()

        lock_card = ctk.CTkFrame(self, fg_color="#111C2E", corner_radius=14,
                                 border_width=1, border_color="#24364D")
        lock_card.pack(fill="x", padx=42, pady=8)
        ctk.CTkLabel(lock_card, text="Automatic vault lock", font=("Segoe UI", 16, "bold"),
                     text_color="#FFFFFF").pack(anchor="w", padx=18, pady=(14, 4))
        ctk.CTkLabel(lock_card,
                     text="Automatically sign out and clear the in-memory vault key after inactivity.",
                     font=("Segoe UI", 12), text_color="#A9B8CC", wraplength=650,
                     justify="left").pack(anchor="w", padx=18, pady=(0, 10))
        options = {0: "Off", 5: "5 minutes", 10: "10 minutes", 15: "15 minutes", 30: "30 minutes"}
        current_value = int(self.app_preferences.get("auto_lock_minutes", 10))
        timeout_menu = ctk.CTkOptionMenu(
            lock_card, values=list(options.values()), width=180,
            command=self.change_auto_lock_setting
        )
        timeout_menu.set(options.get(current_value, "10 minutes"))
        timeout_menu.pack(anchor="w", padx=18, pady=(0, 12))
        ctk.CTkButton(
            lock_card, text="LOCK VAULT NOW", height=38, width=190,
            fg_color="#8F3038", hover_color="#70242B",
            command=self.lock_vault_now
        ).pack(anchor="w", padx=18, pady=(0, 16))

    def lock_vault_now(self):
        if self.operation_running:
            self.show_error("Wait for the current encryption or decryption operation to finish before locking the vault.")
            return
        if not self.vault_key:
            self.show_error("The vault is already locked.")
            return
        confirmed = messagebox.askyesno(
            "Lock SecureVault",
            "This will clear the vault key from memory and sign out this device. Continue?"
        )
        if confirmed:
            self.logout(reason="Your vault was locked. Sign in again to continue.")

    def show_vault_settings(self):
        self._settings_page_header(
            "VAULT SETTINGS",
            "Review the protection used by your current SecureVault session."
        )

        self._settings_info_card(
            self,
            "Encryption standard",
            "AES-256-GCM authenticated encryption is used for protected files "
            "and folders.",
            "ACTIVE IN THE CURRENT ENCRYPTION ENGINE",
            "#22C55E"
        )

        self._settings_info_card(
            self,
            "Vault key status",
            "The vault key is held in application memory while you are signed in.",
            "UNLOCKED — KEY LOADED" if self.vault_key else "LOCKED — NO KEY LOADED",
            "#22C55E" if self.vault_key else "#F59E0B"
        )

        self._settings_info_card(
            self,
            "Local application folder",
            self.project_root
        )

        self._settings_info_card(
            self,
            "Encrypted file format",
            "SecureVault encrypted files use the .svault extension."
        )

    def show_backup_settings(self):
        self._settings_page_header(
            "BACKUP & RECOVERY",
            "Manage the protected copy of your vault key."
        )

        self._settings_info_card(
            self, "Cloud vault-key backup",
            "SecureVault sends the protected vault key to its authenticated cloud backup service. "
            "The vault key itself is not displayed in this screen."
        )
        if self.vault_key:
            ctk.CTkButton(
                self, text="BACK UP VAULT KEY NOW", width=280, height=42,
                fg_color="#0891B2", hover_color="#0E7490",
                command=self.backup_vault_key_now
            ).pack(pady=(8, 12))
        else:
            self._settings_info_card(
                self, "Backup action unavailable",
                "Sign in and unlock your vault before requesting a fresh cloud backup.",
                "VAULT LOCKED", "#F59E0B"
            )

        self._settings_info_card(
            self, "Account recovery",
            "Use Forgot Password on the login screen and complete the email verification flow. "
            "Your existing vault key is retrieved after successful recovery."
        )
        self._settings_info_card(
            self, "Restore verification",
            "A separate cloud integrity check and cross-device restore test are not available here. "
            "A successful backup request does not prove that a second device can restore your vault.",
            "RESTORE TEST STILL REQUIRED", "#F59E0B"
        )

    def show_devices_settings(self):
        self._settings_page_header(
            "LOGIN & DEVICES",
            "Information about the current SecureVault session."
        )

        self._settings_info_card(
            self,
            "Signed-in account",
            self.current_email or "No account is currently signed in."
        )

        self._settings_info_card(
            self,
            "Current operating system",
            f"{platform.system()} {platform.release()}"
        )

        trusted_now = bool(self.cloud.get_local_device_token())
        self._settings_info_card(
            self,
            "Trusted-device status",
            "A protected credential is stored for this Windows profile. Supabase validates it before every VMK retrieval.",
            "TRUSTED ON THIS WINDOWS PROFILE" if trusted_now else "NOT REGISTERED AS TRUSTED",
            "#22C55E" if trusted_now else "#F59E0B"
        )

        self._settings_info_card(
            self,
            "Session controls",
            "Logging out keeps this device trusted. Use Revoke Trust to require email OTP the next time this device signs in."
        )

        if trusted_now:
            self.create_button(
                "REVOKE TRUST FOR THIS DEVICE",
                self.revoke_trust_for_this_device,
                fg_color="#8F3038",
                hover_color="#70242B"
            )

        self.create_button(
            "LOG OUT FROM THIS DEVICE",
            self.logout,
            fg_color="#8F3038",
            hover_color="#70242B"
        )

    def revoke_trust_for_this_device(self):
        if not messagebox.askyesno(
            "Revoke trusted device",
            "A fresh email OTP is required. Send a verification code to your account email?"
        ):
            return
        try:
            self.cloud.send_login_otp(self.current_email)
            self.pending_email = self.current_email
            self.pending_action = "revoke_device"
            self.show_otp_screen(
                "VERIFY DEVICE REVOCATION",
                "Enter the email OTP to revoke trust for this Windows device."
            )
        except Exception as error:
            self.show_error(error)

    def show_notification_settings(self):
        self._settings_page_header(
            "NOTIFICATIONS",
            "Control the operation confirmations shown by this desktop app."
        )

        card = ctk.CTkFrame(self, fg_color="#111C2E", corner_radius=14,
                            border_width=1, border_color="#24364D")
        card.pack(fill="x", padx=42, pady=10)
        ctk.CTkLabel(card, text="Operation confirmations", font=("Segoe UI", 16, "bold"),
                     text_color="#FFFFFF").pack(anchor="w", padx=18, pady=(15, 4))
        ctk.CTkLabel(card,
                     text="Choose whether SecureVault displays a success window after file or folder encryption and decryption. Error alerts remain enabled so failures are not hidden.",
                     font=("Segoe UI", 12), text_color="#A9B8CC", wraplength=650,
                     justify="left").pack(anchor="w", padx=18, pady=(0, 12))
        success_var = ctk.BooleanVar(value=bool(self.app_preferences.get("success_popups", True)))
        ctk.CTkSwitch(
            card, text="Show operation success popups", variable=success_var,
            onvalue=True, offvalue=False,
            command=lambda: self.change_success_popup_preference(success_var.get())
        ).pack(anchor="w", padx=18, pady=(0, 16))

        self._settings_info_card(
            self, "Security emails",
            "Registration, password recovery, email changes, password-change reauthentication, and supported account-security emails are managed by the configured Supabase email templates. Normal login uses your email and password without an OTP prompt. "
            "This desktop setting does not disable or alter those server-generated emails."
        )
        self._settings_info_card(
            self, "First-encryption feedback",
            "The first-encryption feedback request remains available even if routine success popups are turned off."
        )

    def show_about_settings(self):
        self._settings_page_header(
            "ABOUT SECUREVAULT",
            "Your desktop application for protecting files and folders."
        )

        ctk.CTkLabel(
            self,
            text="SECUREVAULT",
            font=("Segoe UI", 30, "bold"),
            text_color="#FFFFFF"
        ).pack(pady=(20, 8))

        ctk.CTkLabel(
            self,
            text="ENCRYPT  •  PROTECT  •  STAY SECURE",
            font=("Segoe UI", 13, "bold"),
            text_color="#22D3EE"
        ).pack(pady=5)

        self._settings_info_card(
            self,
            "Core protection",
            "AES-256-GCM encryption for files and folders."
        )

        self._settings_info_card(
            self,
            "Account security",
            "Email verification, password recovery, and optional "
            "authenticator-based two-factor authentication."
        )

        self._settings_info_card(
            self,
            "Cloud services",
            "Supabase is used for account authentication and protected "
            "vault-key backup services."
        )

        ctk.CTkLabel(
            self,
            text="Development build",
            font=("Segoe UI", 11),
            text_color="#71839B"
        ).pack(pady=10)


    # ==================================================
    # CHANGE EMAIL
    # ==================================================

    def show_change_email_screen(self):

        self.clear_screen()

        self.create_title(
            "CHANGE EMAIL ADDRESS",
            "A verification email will be sent to your new address"
        )

        ctk.CTkLabel(
            self,
            text=f"Current email: {self.current_email}",
            font=("Segoe UI", 13),
            text_color="#22D3EE"
        ).pack(pady=8)

        self.new_email_entry = self.create_entry(
            "Enter new email address"
        )

        self.create_button(
            "SEND EMAIL VERIFICATION",
            self.request_email_change
        )

        ctk.CTkButton(
            self,
            text="Back to Account Settings",
            width=350,
            fg_color="transparent",
            command=self.show_account_settings
        ).pack(pady=8)

    def request_email_change(self):

        new_email = self.new_email_entry.get().strip().lower()

        if not new_email or "@" not in new_email:
            self.show_error("Please enter a valid email address.")
            return

        if new_email == (self.current_email or "").lower():
            self.show_error(
                "This is already your registered email address."
            )
            return

        try:

            self.cloud.update_email(new_email)

            self.pending_email_change = new_email
            self.pending_email = new_email
            self.pending_action = "email_change"

            self.show_otp_screen(
                "VERIFY NEW EMAIL",
                "Enter the email-change verification code sent by Supabase."
            )

        except Exception as e:
            self.show_error(e)

    # ==================================================
    # CHANGE PASSWORD WITH REAUTHENTICATION
    # ==================================================

    def show_change_password_screen(self):

        self.clear_screen()
        self.reauth_code_sent = False

        self.create_title(
            "CHANGE PASSWORD",
            "Verify your identity before changing your password"
        )

        ctk.CTkLabel(
            self,
            text=(
                "Verification code will be sent to:\n"
                f"{self.current_email}"
            ),
            font=("Segoe UI", 14),
            text_color="#22D3EE",
            justify="center"
        ).pack(pady=(0, 12))

        self.create_button(
            "SEND VERIFICATION CODE",
            self.send_reauthentication_code
        )

        self.reauth_otp_entry = self.create_entry(
            "Enter 6-digit verification code"
        )

        self.change_new_password_entry = self.create_entry(
            "New password",
            show="*"
        )

        self.change_confirm_password_entry = self.create_entry(
            "Confirm new password",
            show="*"
        )

        self.create_button(
            "UPDATE PASSWORD",
            self.change_password
        )

        ctk.CTkButton(
            self,
            text="Back to Account Settings",
            width=350,
            fg_color="transparent",
            command=self.show_account_settings
        ).pack(pady=8)

    def send_reauthentication_code(self):

        if not self.current_email:
            self.show_error("Please log in again.")
            return

        try:
            self.cloud.send_reauthentication()

            self.reauth_code_sent = True

            self.show_success(
                "Verification code sent successfully!\n\n"
                "Check your registered email and enter the code."
            )

        except Exception as e:
            self.show_error(e)

    def change_password(self):

        if not self.reauth_code_sent:
            self.show_error(
                "Please send the verification code first."
            )
            return

        nonce = self.reauth_otp_entry.get().strip()
        new_password = self.change_new_password_entry.get()
        confirm_password = self.change_confirm_password_entry.get()

        if not nonce or not new_password or not confirm_password:
            self.show_error("Please fill in all fields.")
            return

        if not nonce.isdigit() or len(nonce) != 6:
            self.show_error(
                "Please enter a valid 6-digit verification code."
            )
            return

        if new_password != confirm_password:
            self.show_error("Passwords do not match.")
            return

        if len(new_password) < 8:
            self.show_error(
                "Password must contain at least 8 characters."
            )
            return

        try:

            self.cloud.update_password_with_reauth(
                new_password,
                nonce
            )

            # Remove credentials and the one-time code from the UI immediately.
            self.reauth_otp_entry.delete(0, "end")
            self.change_new_password_entry.delete(0, "end")
            self.change_confirm_password_entry.delete(0, "end")
            nonce = None
            new_password = None
            confirm_password = None

            self.reauth_code_sent = False

            self.show_success(
                "Password changed successfully!\n\n"
                "Your existing vault key and encrypted files "
                "have not been changed."
            )

            self.show_account_settings()

        except Exception as e:
            self.show_error(e)

    # ==================================================
    # AUTHENTICATOR MANAGEMENT
    # ==================================================

    def show_authenticator_screen(self):

        self.clear_screen()

        self.create_title(
            "AUTHENTICATOR MANAGEMENT",
            "Manage two-factor authentication"
        )

        try:
            factors = self.cloud.list_totp_factors()

        except Exception as e:
            self.show_error(e)
            self.show_account_settings()
            return

        verified_factors = [
            factor for factor in factors
            if factor.get("factor_type") == "totp"
            and factor.get("status") == "verified"
        ]

        if verified_factors:

            ctk.CTkLabel(
                self,
                text="Authenticator is currently enabled.",
                font=("Segoe UI", 15, "bold"),
                text_color="#22C55E"
            ).pack(pady=12)

            for factor in verified_factors:
                ctk.CTkLabel(
                    self,
                    text=(
                        factor.get("friendly_name")
                        or "Authenticator device"
                    ),
                    font=("Segoe UI", 13),
                    text_color="#A9B8CC"
                ).pack(pady=4)

            self.create_button(
                "REMOVE AUTHENTICATOR",
                lambda: self.start_totp_removal(
                    verified_factors[0].get("id")
                ),
                fg_color="#9B3030",
                hover_color="#762323"
            )

        else:

            ctk.CTkLabel(
                self,
                text="No verified authenticator is enabled.",
                font=("Segoe UI", 14),
                text_color="#A9B8CC"
            ).pack(pady=15)

            if factors:
                ctk.CTkLabel(
                    self,
                    text=(
                        "An unfinished authenticator setup exists. "
                        "You may need to finish or remove it."
                    ),
                    font=("Segoe UI", 12),
                    text_color="#FBBF24",
                    wraplength=450
                ).pack(pady=8)

            self.create_button(
                "ENABLE AUTHENTICATOR",
                self.start_totp_enrollment
            )

        ctk.CTkButton(
            self,
            text="Back to Account Settings",
            width=350,
            fg_color="transparent",
            command=self.show_account_settings
        ).pack(pady=12)

    # ==================================================
    # TOTP ENROLLMENT
    # ==================================================

    def start_totp_enrollment(self):

        try:

            result = self.cloud.enroll_totp("SecureVault")

            self.totp_factor_id = result.get("id")

            totp_data = result.get("totp", {})

            self.totp_secret = totp_data.get("secret")
            self.totp_uri = totp_data.get("uri")

            if not self.totp_factor_id or not self.totp_secret:
                raise Exception(
                    "Supabase did not return the authenticator setup details."
                )

            self.show_totp_setup_screen()

        except Exception as e:
            self.show_error(e)

    def show_totp_setup_screen(self):

        self.clear_screen()

        self.create_title(
            "SET UP AUTHENTICATOR",
            "Scan this QR code using Google Authenticator or another TOTP app."
        )

        if not self.totp_uri:
            self.show_error("Authenticator setup URI is missing. Please try again.")
            self.show_authenticator_screen()
            return

        # Generate QR code from the Supabase authenticator URI.
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4
        )

        qr.add_data(self.totp_uri)
        qr.make(fit=True)

        qr_image = qr.make_image(
            fill_color="black",
            back_color="white"
        ).convert("RGB")

        qr_image = qr_image.resize((220, 220))

        # Keep a reference so Tkinter does not discard the image.
        self.totp_qr_image = ctk.CTkImage(
            light_image=qr_image,
            dark_image=qr_image,
            size=(220, 220)
        )

        ctk.CTkLabel(
            self,
            text="",
            image=self.totp_qr_image
        ).pack(pady=12)

        ctk.CTkLabel(
            self,
            text="Scan this QR code with your authenticator app.",
            font=("Segoe UI", 13),
            text_color="#A9B8CC"
        ).pack(pady=5)

        ctk.CTkLabel(
            self,
            text="Can't scan? Enter this setup key manually:",
            font=("Segoe UI", 12),
            text_color="#A9B8CC"
        ).pack(pady=(12, 5))

        ctk.CTkLabel(
            self,
            text=self.totp_secret,
            font=("Cascadia Code", 14, "bold"),
            text_color="#22D3EE",
            wraplength=600
        ).pack(pady=8)

        ctk.CTkLabel(
            self,
            text="Enter the six-digit code displayed by your authenticator app.",
            font=("Segoe UI", 12),
            text_color="#A9B8CC",
            wraplength=600
        ).pack(pady=12)

        self.totp_code_entry = self.create_entry(
            "6-digit authenticator code"
        )

        ctk.CTkButton(
            self,
            text="VERIFY & ENABLE",
            width=300,
            height=45,
            fg_color="#0891B2",
            hover_color="#0E7490",
            command=self.verify_totp_enrollment
        ).pack(pady=15)

        ctk.CTkButton(
            self,
            text="CANCEL",
            width=300,
            height=35,
            fg_color="transparent",
            command=self.show_authenticator_screen
        ).pack(pady=5)


    def verify_totp_enrollment(self):

        code = self.totp_code_entry.get().strip()

        if not code.isdigit() or len(code) != 6:
            self.show_error(
                "Please enter a valid 6-digit authenticator code."
            )
            return

        try:

            challenge = self.cloud.challenge_totp(
                self.totp_factor_id
            )

            challenge_id = challenge.get("id")

            if not challenge_id:
                raise Exception(
                    "Could not create authenticator verification challenge."
                )

            self.cloud.verify_totp(
                self.totp_factor_id,
                challenge_id,
                code
            )

            self.totp_factor_id = None
            self.totp_secret = None

            self.show_success(
                "Authenticator enabled successfully!"
            )

            self.show_authenticator_screen()

        except Exception as e:
            self.show_error(e)

    # ==================================================
    # REMOVE AUTHENTICATOR
    # ==================================================

    def start_totp_removal(self, factor_id):

        if not factor_id:
            self.show_error(
                "Authenticator factor ID was not found."
            )
            return

        self.removal_factor_id = factor_id

        self.clear_screen()

        self.create_title(
            "REMOVE AUTHENTICATOR",
            "Verify your identity before removing two-factor authentication"
        )

        ctk.CTkLabel(
            self,
            text=(
                "Open your authenticator app and enter "
                "the current SecureVault code."
            ),
            font=("Segoe UI", 14),
            text_color="#A9B8CC",
            wraplength=500
        ).pack(pady=15)

        self.removal_code_entry = self.create_entry(
            "Enter 6-digit authenticator code"
        )

        self.create_button(
            "VERIFY AND REMOVE",
            self.verify_and_remove_totp,
            fg_color="#9B3030",
            hover_color="#762323"
        )

        ctk.CTkButton(
            self,
            text="Cancel",
            width=350,
            fg_color="transparent",
            command=self.show_authenticator_screen
        ).pack(pady=8)

    def verify_and_remove_totp(self):

        code = self.removal_code_entry.get().strip()

        if not code.isdigit() or len(code) != 6:
            self.show_error(
                "Please enter a valid 6-digit authenticator code."
            )
            return

        try:

            challenge = self.cloud.challenge_totp(
                self.removal_factor_id
            )

            challenge_id = challenge.get("id")

            if not challenge_id:
                raise Exception(
                    "Could not create authenticator challenge."
                )

            self.cloud.verify_totp(
                self.removal_factor_id,
                challenge_id,
                code
            )

            self.cloud.delete_totp_factor(
                self.removal_factor_id
            )

            self.removal_factor_id = None

            self.show_success(
                "Authenticator removed successfully."
            )

            self.show_authenticator_screen()

        except Exception as e:
            self.show_error(e)

    # ==================================================
    # SUCCESS POPUP FOR ENCRYPTION / DECRYPTION
    # ==================================================

    def show_operation_success_popup(
        self,
        operation_name,
        result=None,
        is_first_encryption=False,
        show_feedback=False
    ):

        popup = ctk.CTkToplevel(self)

        popup.title("SecureVault - Success")
        popup.geometry("480x430")
        popup.resizable(False, False)
        popup.configure(fg_color="#0B1120")
        popup.transient(self)

        self.update_idletasks()

        x = self.winfo_x() + (
            self.winfo_width() - 480
        ) // 2

        y = self.winfo_y() + (
            self.winfo_height() - 430
        ) // 2

        popup.geometry(f"480x430+{x}+{y}")

        popup.grab_set()
        popup.focus_force()

        ctk.CTkLabel(
            popup,
            text="🛡️",
            font=("Segoe UI", 65),
            text_color="#22D3EE"
        ).pack(pady=(30, 10))

        heading = (
            "FIRST ENCRYPTION SUCCESSFUL"
            if is_first_encryption
            else "OPERATION SUCCESSFUL"
        )

        ctk.CTkLabel(
            popup,
            text=heading,
            font=("Segoe UI", 13, "bold"),
            text_color="#22C55E"
        ).pack(pady=5)

        ctk.CTkLabel(
            popup,
            text="Congratulations!",
            font=("Segoe UI", 30, "bold"),
            text_color="#FFFFFF"
        ).pack(pady=(12, 8))

        ctk.CTkLabel(
            popup,
            text=f"{operation_name} completed successfully.",
            font=("Segoe UI", 15, "bold"),
            text_color="#FFFFFF",
            wraplength=400
        ).pack(pady=8)

        description = (
            "Your first file or folder is now secured."
            if is_first_encryption
            else "Your data has been processed successfully."
        )

        ctk.CTkLabel(
            popup,
            text=description,
            font=("Segoe UI", 13),
            text_color="#A9B8CC",
            justify="center"
        ).pack(pady=10)

        ctk.CTkLabel(
            popup,
            text="ENCRYPT • PROTECT • STAY SECURE",
            font=("Segoe UI", 14, "bold"),
            text_color="#22D3EE"
        ).pack(pady=15)

        def close_popup():

            if not popup.winfo_exists():
                return

            if is_first_encryption:

                try:
                    with open(
                        self.first_encryption_flag,
                        "w",
                        encoding="utf-8"
                    ) as file:
                        file.write("completed")

                    self.first_encryption_shown = True

                except OSError as e:
                    self.first_encryption_shown = True
                    self.show_error(
                        "Could not save first-encryption status:\n"
                        f"{e}"
                    )

            popup.destroy()

            if show_feedback and not self.feedback_completed:
                self.show_feedback_screen()
            else:
                self.show_dashboard()

        ctk.CTkButton(
            popup,
            text="CONTINUE TO DASHBOARD",
            width=300,
            height=45,
            fg_color="#0891B2",
            hover_color="#0E7490",
            command=close_popup
        ).pack(pady=15)

        popup.protocol("WM_DELETE_WINDOW", close_popup)

    # ==================================================
    # FEEDBACK
    # ==================================================

    def save_feedback_completion(self):

        try:
            with open(
                self.feedback_flag,
                "w",
                encoding="utf-8"
            ) as file:
                file.write("completed")

        except OSError:
            pass

        self.feedback_completed = True

    def show_feedback_screen(self):

        self.clear_screen()

        self.create_title(
            "SHARE YOUR FEEDBACK",
            "Help us make SecureVault better"
        )

        ctk.CTkLabel(
            self,
            text="How was your first experience?",
            font=("Segoe UI", 17, "bold"),
            text_color="#FFFFFF"
        ).pack(pady=(15, 15))

        self.selected_feedback_rating = 5

        rating_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        rating_frame.pack(pady=10)

        self.rating_buttons = []

        def select_rating(rating):

            self.selected_feedback_rating = rating

            for index, button in enumerate(
                self.rating_buttons,
                start=1
            ):
                button.configure(
                    fg_color=(
                        "#0891B2"
                        if index <= rating
                        else "#1B2A40"
                    )
                )

        for rating in range(1, 6):

            button = ctk.CTkButton(
                rating_frame,
                text="★",
                width=48,
                height=45,
                font=("Segoe UI", 23),
                fg_color="#0891B2",
                hover_color="#0E7490",
                command=lambda r=rating: select_rating(r)
            )

            button.pack(side="left", padx=5)
            self.rating_buttons.append(button)

        ctk.CTkLabel(
            self,
            text="Tell us about your experience",
            font=("Segoe UI", 14),
            text_color="#A9B8CC"
        ).pack(pady=(20, 8))

        self.feedback_text = ctk.CTkTextbox(
            self,
            width=420,
            height=140,
            font=("Segoe UI", 13),
            wrap="word"
        )
        self.feedback_text.pack(pady=8)

        self.create_button(
            "SUBMIT FEEDBACK",
            self.submit_user_feedback,
            width=300
        )

        ctk.CTkButton(
            self,
            text="SKIP FOR NOW",
            width=300,
            height=35,
            fg_color="transparent",
            hover=False,
            command=self.skip_feedback
        ).pack(pady=5)

    def submit_user_feedback(self):

        rating = self.selected_feedback_rating

        feedback = self.feedback_text.get(
            "1.0",
            "end"
        ).strip()

        if not feedback:
            self.show_error("Please enter your feedback.")
            return

        if len(feedback) > 2000:
            self.show_error(
                "Feedback cannot exceed 2000 characters."
            )
            return

        try:

            self.cloud.submit_feedback(
                rating,
                feedback
            )

            self.save_feedback_completion()

            self.show_success(
                "Thank you for your feedback!\n\n"
                "Your response has been securely submitted."
            )

            self.show_dashboard()

        except Exception as e:
            self.show_error(e)

    def skip_feedback(self):
        self.save_feedback_completion()
        self.show_dashboard()

    # ==================================================
    # PROGRESS CALLBACK
    # ==================================================

    def update_progress(self, value, *args):

        def update():

            if args and isinstance(args[0], (int, float)):

                total = float(args[0])

                if total > 0:
                    progress = (float(value) / total) * 100
                else:
                    progress = 0

            else:
                progress = float(value)

            progress = max(0, min(100, progress))

            self.progress_bar.set(progress / 100)

            self.progress_label.configure(
                text=f"Progress: {progress:.1f}%"
            )

        self.after(0, update)

    # ==================================================
    # ENCRYPTION / DECRYPTION OPERATIONS
    # ==================================================

    def run_operation(self, operation, path, operation_name):

        if self.operation_running:
            self.show_error(
                "Another operation is already running."
            )
            return

        if not self.vault_key:
            self.show_error(
                "Vault is locked. Please log in again."
            )
            return

        self.operation_running = True

        self.progress_bar.set(0)
        self.progress_label.configure(text="Starting...")

        def worker():

            try:

                result = operation(
                    path,
                    self.vault_key,
                    progress_callback=self.update_progress
                )

                self.after(
                    0,
                    lambda: self.operation_success(
                        operation_name,
                        result
                    )
                )

            except Exception as e:

                error_message = str(e)

                self.after(
                    0,
                    lambda: self.operation_error(error_message)
                )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def operation_success(self, operation_name, result):

        self.operation_running = False

        self.progress_bar.set(1)
        self.progress_label.configure(
            text="Completed successfully"
        )

        is_encryption = operation_name in (
            "File encryption",
            "Folder encryption"
        )

        is_first_encryption = (
            is_encryption
            and not self.first_encryption_shown
        )

        show_feedback = (
            is_first_encryption
            and not self.feedback_completed
        )

        if self.app_preferences.get("success_popups", True):
            self.show_operation_success_popup(
                operation_name=operation_name,
                result=result,
                is_first_encryption=is_first_encryption,
                show_feedback=show_feedback
            )
        else:
            if is_first_encryption:
                try:
                    with open(self.first_encryption_flag, "w", encoding="utf-8") as file:
                        file.write("completed")
                    self.first_encryption_shown = True
                except OSError:
                    self.first_encryption_shown = True
                if show_feedback:
                    self.show_feedback_screen()
                    return
            self.show_dashboard()

    def operation_error(self, error):

        self.operation_running = False

        self.progress_bar.set(0)
        self.progress_label.configure(
            text="Operation failed"
        )

        self.show_error(error)

    # ==================================================
    # FILE ENCRYPTION
    # ==================================================

    def encrypt_file_action(self):

        path = filedialog.askopenfilename(
            title="Select file to encrypt"
        )

        if path:
            self.run_operation(
                encrypt_file,
                path,
                "File encryption"
            )

    def decrypt_file_action(self):

        path = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[
                ("SecureVault files", "*.svault"),
                ("All files", "*.*")
            ]
        )

        if path:
            self.run_operation(
                decrypt_file,
                path,
                "File decryption"
            )

    def encrypt_folder_action(self):

        path = filedialog.askdirectory(
            title="Select folder to encrypt"
        )

        if path:
            self.run_operation(
                encrypt_folder,
                path,
                "Folder encryption"
            )

    def decrypt_folder_action(self):

        path = filedialog.askopenfilename(
            title="Select encrypted folder file",
            filetypes=[
                ("SecureVault folder files", "*.svault"),
                ("All files", "*.*")
            ]
        )

        if path:
            self.run_operation(
                decrypt_folder,
                path,
                "Folder decryption"
            )

    # ==================================================
    # LOGOUT
    # ==================================================

    def logout(self, reason=None):

        if self.operation_running:
            self.show_error(
                "Please wait until the current operation finishes."
            )
            return

        self.vault_key = None
        self.current_email = None

        self.pending_email = None
        self.pending_password = None
        self.pending_action = None
        self.pending_email_change = None

        self.reauth_code_sent = False

        self.totp_factor_id = None
        self.totp_challenge_id = None
        self.totp_secret = None

        try:
            self.cloud.logout()
        except Exception:
            pass

        self.show_login_screen()
        if reason:
            self.after(250, lambda: self.show_success(reason))


if __name__ == "__main__":

    app = SecureVaultApp()
    app.mainloop()
