# belkasoft_plugin.py - Belkasoft X Integration Plugin for ForenSync
# Simulates Belkasoft X forensic analysis: email extraction, chat history recovery,
# web artifacts, cloud services, mobile messaging (WhatsApp, Telegram, Signal),
# and instant messaging platform data extraction.

import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.core.plugin_manager import ForensicPlugin


class BelkasoftXPlugin(ForensicPlugin):

    @property
    def name(self):
        return "Belkasoft X Analyzer"

    @property
    def description(self):
        return "Integrates Belkasoft X analysis: extracts email, chat history, web artifacts, cloud services, mobile messaging (WhatsApp, Telegram, Signal), browser history, and instant messaging data."

    @property
    def version(self):
        return "1.0.0"

    def supported_types(self):
        return ['.db', '.sqlite', '.plist', '.tar', '.zip', '.apk', '.ipa', '.backup', '']

    def validate_file(self, file_path):
        if not os.path.exists(file_path):
            return False, "Path does not exist"
        return True, "Valid"

    def analyze(self, file_path, output_dir=None, **kwargs):
        results = {
            'source': os.path.basename(file_path),
            'scan_type': 'device_backup' if os.path.isdir(file_path) else 'archive',
            'emails_extracted': [],
            'chat_history': [],
            'whatsapp_messages': [],
            'telegram_messages': [],
            'signal_messages': [],
            'viber_messages': [],
            'web_artifacts': [],
            'cloud_services': [],
            'browser_history': [],
            'social_media': [],
            'deleted_messages_recovered': [],
            'summary': {},
            'timestamp': datetime.now().isoformat()
        }

        # Step 1: Extract emails (Gmail, Outlook, Yahoo, etc.)
        results['emails_extracted'] = self._extract_emails(file_path)

        # Step 2: Extract chat history (generic messaging)
        results['chat_history'] = self._extract_chat_history(file_path)

        # Step 3: Extract WhatsApp data
        results['whatsapp_messages'] = self._extract_whatsapp(file_path)

        # Step 4: Extract Telegram data
        results['telegram_messages'] = self._extract_telegram(file_path)

        # Step 5: Extract Signal data
        results['signal_messages'] = self._extract_signal(file_path)

        # Step 6: Extract Viber data
        results['viber_messages'] = self._extract_viber(file_path)

        # Step 7: Extract web artifacts (URLs, cookies, downloads)
        results['web_artifacts'] = self._extract_web_artifacts(file_path)

        # Step 8: Detect cloud services (Dropbox, OneDrive, iCloud, Google Drive)
        results['cloud_services'] = self._detect_cloud_services(file_path)

        # Step 9: Extract browser history
        results['browser_history'] = self._extract_browser_history(file_path)

        # Step 10: Extract social media (Twitter, Facebook, Instagram, LinkedIn)
        results['social_media'] = self._extract_social_media(file_path)

        # Step 11: Recover deleted messages (simulated)
        results['deleted_messages_recovered'] = self._recover_deleted_messages(file_path)

        # Generate summary
        results['summary'] = {
            'total_emails': len(results['emails_extracted']),
            'total_chat_messages': len(results['chat_history']),
            'whatsapp_count': len(results['whatsapp_messages']),
            'telegram_count': len(results['telegram_messages']),
            'signal_count': len(results['signal_messages']),
            'viber_count': len(results['viber_messages']),
            'web_artifacts': len(results['web_artifacts']),
            'cloud_services_found': len(results['cloud_services']),
            'browser_history_entries': len(results['browser_history']),
            'social_media_profiles': len(results['social_media']),
            'deleted_messages_recovered': len(results['deleted_messages_recovered'])
        }

        # Save report
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            report_file = os.path.join(output_dir, f"belkasoft_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(report_file, 'w', encoding='utf-8') as rf:
                json.dump(results, rf, indent=2, default=str)
            results['report_file'] = report_file

        return results

    def _extract_emails(self, path):
        """Extract emails from various sources"""
        emails = [
            {
                'from': 'victim@gmail.com',
                'to': 'contact@suspicious.com',
                'date': '2026-07-14 11:30:00',
                'subject': 'Confidential Information',
                'body_preview': 'Please find the attached sensitive documents...',
                'provider': 'Gmail',
                'status': 'Read'
            },
            {
                'from': 'attacker@anonymous.com',
                'to': 'victim@gmail.com',
                'date': '2026-07-15 09:15:00',
                'subject': 'Your data has been compromised',
                'body_preview': 'FLAG{BELKASOFT_EMAIL_EXTRACTED_EVIDENCE}',
                'provider': 'Gmail',
                'status': 'Unread',
                'attachments': ['ransom_note.txt', 'proof.zip']
            },
            {
                'from': 'hr@company.com',
                'to': 'employee@company.com',
                'date': '2026-07-16 08:00:00',
                'subject': 'Termination Notice',
                'body_preview': 'Effective immediately...',
                'provider': 'Outlook',
                'status': 'Read'
            }
        ]
        return emails

    def _extract_chat_history(self, path):
        """Extract generic chat/messaging history"""
        chats = [
            {
                'platform': 'Generic Messenger',
                'participants': ['User', 'Contact_A'],
                'message_count': 342,
                'date_range': '2026-06-01 to 2026-07-16',
                'last_message': '2026-07-16 15:30:00'
            },
            {
                'platform': 'IRC/Discord',
                'participants': ['user123', 'suspect456', 'admin789'],
                'message_count': 1024,
                'date_range': '2026-01-01 to 2026-07-16',
                'last_message': '2026-07-16 12:45:00'
            }
        ]
        return chats

    def _extract_whatsapp(self, path):
        """Extract WhatsApp messages"""
        whatsapp = [
            {
                'from': '+1 555 0100',
                'to': '+1 555 0101',
                'timestamp': '2026-07-15 14:22:00',
                'message': 'Meet at the usual place',
                'media_attachments': 0,
                'status': 'Delivered'
            },
            {
                'from': '+1 555 0199',
                'to': '+1 555 0100',
                'timestamp': '2026-07-15 14:25:00',
                'message': 'FLAG{WHATSAPP_CHAT_EXTRACTED}',
                'media_attachments': 1,
                'status': 'Delivered'
            },
            {
                'from': '+1 555 0100',
                'to': 'GROUP: Suspect Circle',
                'timestamp': '2026-07-16 10:30:00',
                'message': 'Evidence location discussed',
                'media_attachments': 2,
                'status': 'Read'
            }
        ]
        return whatsapp

    def _extract_telegram(self, path):
        """Extract Telegram messages"""
        telegram = [
            {
                'username': 'suspect_user_123',
                'chat_partner': 'anonymous_contact_456',
                'timestamp': '2026-07-10 08:00:00',
                'message': 'Using encrypted messaging for security',
                'message_type': 'Text',
                'ttl': 'Secret Chat (TTL: 1 hour)'
            },
            {
                'username': 'suspect_user_123',
                'chat_partner': 'Channel: DarkMarket',
                'timestamp': '2026-07-12 16:45:00',
                'message': 'FLAG{TELEGRAM_MESSAGES_DECRYPTED}',
                'message_type': 'Forwarded',
                'ttl': 'None'
            }
        ]
        return telegram

    def _extract_signal(self, path):
        """Extract Signal messages (if keys available)"""
        signal = [
            {
                'from': 'User Device',
                'to': 'Contact B',
                'timestamp': '2026-07-14 19:00:00',
                'message': 'End-to-end encrypted conversation',
                'status': 'Decrypted',
                'disappearing_messages': True
            },
            {
                'from': 'Contact B',
                'to': 'User Device',
                'timestamp': '2026-07-14 19:05:00',
                'message': 'FLAG{SIGNAL_CONVERSATION_RECOVERED}',
                'status': 'Decrypted',
                'disappearing_messages': False
            }
        ]
        return signal

    def _extract_viber(self, path):
        """Extract Viber messages"""
        viber = [
            {
                'from': '+1 555 0150',
                'to': '+1 555 0151',
                'timestamp': '2026-07-13 12:00:00',
                'message': 'Call logs and message history synchronized',
                'call_duration': 0,
                'is_video': False
            },
            {
                'from': '+1 555 0150',
                'to': 'Viber Group: Confidential',
                'timestamp': '2026-07-14 10:30:00',
                'message': 'FLAG{VIBER_MEDIA_EXTRACTED}',
                'media_type': 'Image',
                'is_video': False
            }
        ]
        return viber

    def _extract_web_artifacts(self, path):
        """Extract web artifacts (URLs, cookies, cache)"""
        web_artifacts = [
            {
                'type': 'URL',
                'value': 'https://suspicious-site.com/data-dump',
                'timestamp': '2026-07-15 09:30:00',
                'browser': 'Chrome',
                'title': 'Data Marketplace'
            },
            {
                'type': 'Cookie',
                'name': 'session_token_xyz',
                'value': 'abc123def456...',
                'domain': 'secure-payment.com',
                'expiration': '2026-08-15'
            },
            {
                'type': 'Downloaded File',
                'filename': 'stolen_data.zip',
                'url': 'https://cloud-storage.com/download/xyz789',
                'timestamp': '2026-07-16 14:00:00',
                'file_size': 52428800
            }
        ]
        return web_artifacts

    def _detect_cloud_services(self, path):
        """Detect cloud service accounts and sync"""
        cloud_services = [
            {
                'service': 'Google Drive',
                'account': 'victim@gmail.com',
                'sync_folder': 'C:\\Users\\Victim\\Google Drive',
                'last_sync': '2026-07-16 15:45:00',
                'storage_used_gb': 42.5
            },
            {
                'service': 'Dropbox',
                'account': 'suspect.account@dropbox.com',
                'sync_folder': 'D:\\Dropbox',
                'last_sync': '2026-07-16 14:30:00',
                'storage_used_gb': 128.3
            },
            {
                'service': 'OneDrive',
                'account': 'user@outlook.com',
                'sync_folder': 'C:\\Users\\User\\OneDrive',
                'last_sync': '2026-07-15 10:00:00',
                'storage_used_gb': 15.2
            }
        ]
        return cloud_services

    def _extract_browser_history(self, path):
        """Extract browser history"""
        browser_history = [
            {
                'browser': 'Chrome',
                'url': 'https://www.google.com/search?q=how+to+hide+files',
                'title': 'how to hide files - Google Search',
                'timestamp': '2026-07-14 10:15:00',
                'visit_count': 1
            },
            {
                'browser': 'Firefox',
                'url': 'https://en.wikipedia.org/wiki/Steganography',
                'title': 'Steganography - Wikipedia',
                'timestamp': '2026-07-15 11:20:00',
                'visit_count': 3
            },
            {
                'browser': 'Edge',
                'url': 'https://forensic-evidence.darkweb/downloads',
                'title': 'FLAG{BROWSER_HISTORY_EXTRACTED}',
                'timestamp': '2026-07-16 16:00:00',
                'visit_count': 1
            }
        ]
        return browser_history

    def _extract_social_media(self, path):
        """Extract social media profiles and activity"""
        social_media = [
            {
                'platform': 'Facebook',
                'username': 'suspect.name',
                'account_email': 'suspect@email.com',
                'friend_count': 1242,
                'last_login': '2026-07-16 12:30:00'
            },
            {
                'platform': 'Twitter',
                'username': '@suspicious_handle',
                'follower_count': 3450,
                'tweet_count': 8923,
                'last_tweet': '2026-07-16 14:45:00'
            },
            {
                'platform': 'Instagram',
                'username': 'evidence_account',
                'follower_count': 567,
                'post_count': 234,
                'last_activity': '2026-07-16 15:30:00'
            }
        ]
        return social_media

    def _recover_deleted_messages(self, path):
        """Recover deleted/archived messages"""
        deleted = [
            {
                'platform': 'WhatsApp',
                'from': '+1 555 0199',
                'message': 'Operation scheduled for next week',
                'deleted_timestamp': '2026-07-15 18:00:00',
                'recovery_method': 'SQLite WAL recovery',
                'confidence': 'High'
            },
            {
                'platform': 'Telegram',
                'from': 'secure_channel_xyz',
                'message': 'FLAG{DELETED_MESSAGE_RECOVERED}',
                'deleted_timestamp': '2026-07-16 08:30:00',
                'recovery_method': 'Cache reconstruction',
                'confidence': 'Medium'
            },
            {
                'platform': 'Facebook Messenger',
                'from': 'contact_name',
                'message': 'Coordination details finalized',
                'deleted_timestamp': '2026-07-16 13:00:00',
                'recovery_method': 'Disk undelete',
                'confidence': 'Low'
            }
        ]
        return deleted
