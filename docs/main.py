import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import re
import sys
import signal
import threading
from collections import deque
import hashlib

# =================================================================================
# --- Final Command & Control Bot (Cleaned, no FXC branding) ---
# =================================================================================
# Version: Cleaned & Improved
# Author: Israel & Gemini + Monica (LLM assistant)
# =================================================================================

# --- Configuration ---
BOT_NAME = "Ivory Coast Numbers"
EMAIL = "imodumicheal519@gmail.com"
PASSWORD = "Aliumicheal23"
MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiWAwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = "7398183100:AAG4qywWXknxi7gwK6OY-4vh3XmiUmdxrAc"
GROUP_CHAT_ID_FOR_LISTS = "-1002772196796"
DM_CHAT_ID = "7864059689"

# --- API Endpoints ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
SMS_HISTORY_PAGE_URL = f"{BASE_URL}/portal/sms/test/sms?app=WhatsApp"
SMS_HISTORY_API_URL = f"{BASE_URL}/portal/sms/test/sms"
TEST_NUMBERS_PAGE_URL = f"{BASE_URL}/portal/numbers/test"
TEST_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/test"
ADD_NUMBER_API_URL = f"{BASE_URL}/portal/numbers/termination/number/add"
MY_NUMBERS_URL = f"{BASE_URL}/portal/live/my_sms"
GET_NUMBER_LIST_API_URL = f"{BASE_URL}/portal/live/getNumbers"
REMOVE_ALL_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/return/allnumber/bluck"

RECEIVED_SMS_PAGE_URL = f"{BASE_URL}/portal/sms/received"
GET_SMS_RANGES_URL = f"{BASE_URL}/portal/sms/received/getsms"
GET_SMS_NUMBERS_IN_RANGE_URL = f"{BASE_URL}/portal/sms/received/getsms/number"
GET_SMS_MESSAGES_FOR_NUMBER_URL = f"{BASE_URL}/portal/sms/received/getsms/number/sms"

# --- Global variables ---
current_session = None
api_csrf_token = None  # For acquisition/general APIs
sms_getter_stop_event = threading.Event()
reported_sms_hashes = deque(maxlen=2000)  # To avoid duplicate SMS notifications
otp_cache = {}  # Cache OTPs by phone number for quick Telegram replies
otp_cache_lock = threading.Lock()  # To protect otp_cache in multithreaded access

# State for acquisition confirmation after /start1 command
acquisition_pending = False
pending_number_info = None  # (range_name, full_number)
pending_user_id = None  # user who triggered acquisition prompt

# Track users who misused commands for playful warnings
user_misuse_counts = {}

# Admin username constant
ADMIN_USERNAME = "FXCNUMBERSadmin"

# =================================================================================
# --- Helper Functions ---
# =================================================================================

def send_telegram_message(chat_id, text, is_operational=False):
    if is_operational:
        text += f"\n\n🤖 _{BOT_NAME}_"
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        response.raise_for_status()
        print(f"[TG] Sent to {chat_id}: \"{text[:70].replace(chr(10), ' ')}...\"")
    except Exception as e:
        print(f"[!] TELEGRAM ERROR: Failed to send to {chat_id}: {e}")

def extract_otp_from_text(text):
    # Match 6 digit codes possibly separated by space or dash (e.g. 123456 or 123-456)
    match = re.search(r'\b(\d{3}[- ]?\d{3})\b', text)
    if match:
        otp = match.group(1)
        return otp.replace('-', '').replace(' ', '')
    # fallback to any 4-7 digit number
    match = re.search(r'\b(\d{4,7})\b', text)
    if match:
        return match.group(1)
    return None

def process_and_report_sms(phone_number, sender_cli, message_content, message_time_obj):
    # Skip messages older than 5 minutes (300 seconds)
    if (datetime.utcnow() - message_time_obj).total_seconds() > 300:
        return

    sms_hash = hashlib.md5(f"{phone_number}-{message_content}".encode('utf-8')).hexdigest()

    if sms_hash not in reported_sms_hashes:
        reported_sms_hashes.append(sms_hash)
        print(f"[SMS Detected] Number: {phone_number}, Sender: {sender_cli}, Message: {message_content[:70]}...")

        otp_code = extract_otp_from_text(message_content)

        notification_text = f"For `{phone_number}`\nMessage: `{message_content}`\n"
        if otp_code:
            notification_text += f"OTP: `{otp_code}`\n"
            # Update OTP cache for Telegram listener
            with otp_cache_lock:
                otp_cache[phone_number] = otp_code
        notification_text += "---\nMade by me 😎"

        send_telegram_message(DM_CHAT_ID, notification_text, is_operational=True)
        send_telegram_message(GROUP_CHAT_ID_FOR_LISTS, notification_text, is_operational=False)

# =================================================================================
# --- Telegram Listener (On-demand code requests and command handling) ---
# =================================================================================

def telegram_listener_task(session):
    global acquisition_pending, pending_number_info, pending_user_id

    print("[*] Starting Telegram Group Assistant...")
    offset = None
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

    while not sms_getter_stop_event.is_set():
        try:
            params = {"timeout": 30, "offset": offset, "allowed_updates": ["message"]}
            resp = requests.get(f"{api_url}/getUpdates", params=params, timeout=35)
            resp.raise_for_status()
            updates = resp.json()["result"]

            for update in updates:
                offset = update["update_id"] + 1

                if "message" not in update:
                    continue

                msg = update.get("message", {})
                chat = msg.get("chat", {})
                user = msg.get("from", {})
                text = msg.get("text", "").strip()
                chat_id = chat.get("id")
                is_group = chat.get("type", "").endswith("group")
                username = user.get("username", user.get("first_name", "User"))
                user_id = user.get("id")

                # Handle playful warnings for unauthorized command use
                def playful_warning():
                    count = user_misuse_counts.get(user_id, 0) + 1
                    user_misuse_counts[user_id] = count
                    if count == 1:
                        send_telegram_message(chat_id, "Ole 😂💔 you are not allowed to use me like that 🤪😜😛😋 you self go do juju 🤪💔")
                    else:
                        send_telegram_message(chat_id, "walai if you do that again I go remove you 😂 I just dey play ni Sha")

                # Handle /start1 command: Only admin can start acquisition prompt in group
                if text == "/start1":
                    if username != ADMIN_USERNAME:
                        playful_warning()
                        continue

                    # Start acquisition prompt by scanning live feed once and asking in group for confirmation
                    # For demo, simulate finding a number "Ivory Coast" and phone number "2250757949906"
                    range_name = "Ivory Coast"
                    full_number = "2250757949906"

                    # Save pending acquisition info
                    acquisition_pending = True
                    pending_number_info = (range_name, full_number)
                    pending_user_id = user_id

                    prompt_text = f"Do you want to acquire this number {range_name}?\nNumber: `{full_number}`\nReply with 'y' or 'n'."
                    send_telegram_message(chat_id, prompt_text)
                    continue

                # If acquisition is pending and user replies 'y' or 'n' in group (only admin allowed)
                if acquisition_pending and is_group and user_id == pending_user_id and text.lower() in ['y', 'n']:
                    range_name, full_number = pending_number_info
                    if text.lower() == 'y':
                        send_telegram_message(chat_id, f"Acquiring number `{full_number}` from {range_name}...")
                        success = acquire_and_process_number(session, range_name, full_number)
                        if success:
                            send_telegram_message(chat_id, f"✅ Number `{full_number}` successfully acquired and OTP watcher started.")
                        else:
                            send_telegram_message(chat_id, f"❌ Failed to acquire number `{full_number}`.")
                    else:
                        send_telegram_message(chat_id, "Okay, skipping this number. Waiting for next target...")

                    acquisition_pending = False
                    pending_number_info = None
                    pending_user_id = None
                    continue

                # Handle /next command - admin only - fetch next batch or next number
                if text == "/next":
                    if username != ADMIN_USERNAME:
                        playful_warning()
                        continue
                    send_telegram_message(chat_id, "Fetching next batch of numbers... (Simulated)")
                    range_name = "Ivory Coast"
                    full_number = "2250757947915"
                    acquisition_pending = True
                    pending_number_info = (range_name, full_number)
                    pending_user_id = user_id
                    prompt_text = f"Do you want to acquire this number {range_name}?\nNumber: `{full_number}`\nReply with 'y' or 'n'."
                    send_telegram_message(chat_id, prompt_text)
                    continue

                # Handle /stop command - admin only
                if text == "/stop":
                    if username != ADMIN_USERNAME:
                        playful_warning()
                        continue
                    sms_getter_stop_event.set()
                    send_telegram_message(chat_id, "Boss 😒 man have stopped the bot")
                    continue

                # Handle tagging bot with "werey" - only respond if admin
                if is_group and text.lower() == "werey" and username == ADMIN_USERNAME:
                    send_telegram_message(chat_id, "odeh shebi nah you create me and I dey abuse you")
                    continue

                # Block unauthorized users from using restricted commands
                if text in ["/search", "/start1", "/next", "/stop"] and username != ADMIN_USERNAME:
                    playful_warning()
                    continue

                # Respond only to numeric messages longer than 8 digits (phone numbers) in group
                if is_group and text.isdigit() and len(text) > 8:
                    print(f"--- On-Demand Code Check for {text} requested by @{username} in chat {chat_id} ---")

                    # First check OTP cache from polling
                    with otp_cache_lock:
                        cached_otp = otp_cache.get(text)

                    if cached_otp:
                        reply_text = f"✅ @{username}, cached code for `{text}` is: `{cached_otp}`"
                        send_telegram_message(chat_id, reply_text)
                        continue

                    # Fallback: Query older SMS_HISTORY_API_URL
                    params_sms_history = {'app': 'WhatsApp', 'search[value]': text, '_': int(time.time() * 1000)}
                    headers_sms_history = {
                        'Accept': 'application/json, text/javascript, */*; q=0.01',
                        'Referer': SMS_HISTORY_PAGE_URL,
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                    api_response_sms_history = session.get(SMS_HISTORY_API_URL, params=params_sms_history, headers=headers_sms_history)
                    api_response_sms_history.raise_for_status()
                    data_sms_history = api_response_sms_history.json()

                    reply_text = f"❌ @{username}, code not received for `{text}`"
                    if data_sms_history.get('data'):
                        for sms_entry in data_sms_history['data']:
                            sms_number_html = sms_entry.get('termination', {}).get('test_number', '')
                            sms_number = BeautifulSoup(sms_number_html, 'html.parser').get_text(strip=True)
                            if sms_number == text:
                                message_data = sms_entry.get('messagedata', '')
                                otp_code = extract_otp_from_text(message_data)
                                if otp_code:
                                    reply_text = f"✅ @{username}, code for `{text}` is: `{otp_code}`"
                                    with otp_cache_lock:
                                        otp_cache[text] = otp_code
                                    break
                    send_telegram_message(chat_id, reply_text)

        except requests.exceptions.RequestException as req_e:
            print(f"[!!!] Network error in Telegram Listener thread: {req_e}")
            time.sleep(10)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in Telegram Listener thread: {e}")
            time.sleep(10)

# =================================================================================
# --- Number Acquisition and OTP Fetching ---
# =================================================================================

def acquire_and_process_number(session, number_range_name, phone_number_to_process):
    global api_csrf_token
    print(f"\n--- Acquiring Number: {phone_number_to_process} ---")
    try:
        # Step 1: Get fresh CSRF token from TEST_NUMBERS_PAGE_URL
        page_response = session.get(TEST_NUMBERS_PAGE_URL)
        page_response.raise_for_status()
        soup = BeautifulSoup(page_response.text, 'html.parser')
        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if not token_tag:
            raise Exception("Could not find CSRF token on TEST_NUMBERS_PAGE_URL for acquisition.")
        api_csrf_token = token_tag['content']
        print(f"[+] Acquired API CSRF Token for acquisition: {api_csrf_token}")

        # Step 2: Search for the number to get its internal ID
        params = {
            'draw': '1',
            'columns[0][data]': 'range',
            'columns[1][data]': 'test_number',
            'columns[2][data]': 'term',
            'columns[3][data]': 'P2P',
            'columns[4][data]': 'A2P',
            'columns[5][data]': 'Limit_Range',
            'columns[6][data]': 'limit_cli_a2p',
            'columns[7][data]': 'limit_did_a2p',
            'columns[8][data]': 'limit_cli_did_a2p',
            'columns[9][data]': 'limit_cli_p2p',
            'columns[10][data]': 'limit_did_p2p',
            'columns[11][data]': 'limit_cli_did_p2p',
            'columns[12][data]': 'updated_at',
            'columns[13][data]': 'action',
            'columns[13][searchable]': 'false',
            'columns[13][orderable]': 'false',
            'order[0][column]': '1',
            'order[0][dir]': 'asc',
            'start': '0',
            'length': '50',
            'search[value]': phone_number_to_process,
            '_': int(time.time() * 1000),
        }
        search_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': TEST_NUMBERS_PAGE_URL,
            'X-CSRF-TOKEN': api_csrf_token,
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': session.headers['User-Agent']
        }
        search_response = session.get(TEST_NUMBERS_API_URL, params=params, headers=search_headers)
        search_response.raise_for_status()
        search_data = search_response.json()

        if not search_data.get('data') or not search_data['data']:
            print(f"[!] Search failed. Number {phone_number_to_process} may have been taken or not found.")
            return False

        found_number_id = search_data['data'][0].get('id')
        if not found_number_id:
            print(f"[!] Could not find 'id' for {phone_number_to_process} in search data.")
            return False
        print(f"[+] Found Termination ID: {found_number_id}")

        # Step 3: Add the number using the found ID
        print(f"\n--- Attempting to Add {phone_number_to_process} ---")
        add_payload = {'_token': api_csrf_token, 'id': found_number_id}
        add_headers = search_headers.copy()
        add_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        add_headers['Accept'] = 'application/json'

        add_response = session.post(ADD_NUMBER_API_URL, data=add_payload, headers=add_headers)
        print(f"[DEBUG] Add number response status: {add_response.status_code}")
        print(f"[DEBUG] Add number response text: {add_response.text[:300]}")

        try:
            add_data = add_response.json()
        except Exception as json_err:
            print(f"[!] JSON decode error: {json_err}")
            send_telegram_message(DM_CHAT_ID,
                                  f"❌ *Acquisition Error*\n\nFailed to parse JSON response when adding `{phone_number_to_process}`.\nResponse text:\n{add_response.text[:500]}",
                                  is_operational=True)
            return False

        if "done" in add_data.get("message", "").lower():
            print("[SUCCESS] Server responded 'done'.")
            send_telegram_message(DM_CHAT_ID,
                                  f"✅ *Number Added*\n\nSuccessfully added `{phone_number_to_process}` to the account.",
                                  is_operational=True)

            # Optionally fetch and send full number list
            get_and_send_number_list(session, found_number_id, api_csrf_token, number_range_name)

            # Start real-time OTP fetcher in a separate thread
            otp_thread = threading.Thread(target=realtime_otp_fetcher,
                                          args=(session, phone_number_to_process, number_range_name),
                                          daemon=True)
            otp_thread.start()

            return True
        else:
            error_message = add_data.get("message", "Unknown error or 'message' not in response.")
            print(f"[!] Add action FAILED: {error_message}")
            send_telegram_message(DM_CHAT_ID,
                                  f"❌ *Add Failed*\n\nCould not add `{phone_number_to_process}`. Reason: `{error_message}`",
                                  is_operational=True)
            return False

    except Exception as e:
        print(f"[!] Error during acquisition for {phone_number_to_process}: {e}")
        send_telegram_message(DM_CHAT_ID,
                              f"❌ *Acquisition Error*\n\nAn error occurred during acquisition of `{phone_number_to_process}`: `{e}`",
                              is_operational=True)
        return False


        if "done" in add_data.get("message", "").lower():
            print("[SUCCESS] Server responded 'done'.")
            send_telegram_message(DM_CHAT_ID, f"✅ *Number Added*\n\nSuccessfully added `{phone_number_to_process}` to the account.", is_operational=True)

            # Fetch and send full number list (optional)
            get_and_send_number_list(session, found_number_id, api_csrf_token, number_range_name)

            # Start OTP fetcher for this number in a separate thread so polling can continue
            otp_thread = threading.Thread(target=realtime_otp_fetcher, args=(session, phone_number_to_process, number_range_name), daemon=True)
            otp_thread.start()

            return True
        else:
            error_message = add_data.get("message", "Unknown error or 'message' not in response.")
            print(f"[!] Add action FAILED: {error_message}")
            send_telegram_message(DM_CHAT_ID, f"❌ *Add Failed*\n\nCould not add `{phone_number_to_process}`. Reason: `{error_message}`", is_operational=True)
            return False

    except Exception as e:
        print(f"[!] Error during acquisition for {phone_number_to_process}: {e}")
        send_telegram_message(DM_CHAT_ID, f"❌ *Acquisition Error*\n\nAn error occurred during acquisition of `{phone_number_to_process}`: `{e}`", is_operational=True)
        return False

def get_and_send_number_list(session, termination_id, current_api_csrf_token, range_name):
    print("\n--- Fetching Full Number List ---")
    try:
        payload = {'termination_id': termination_id, '_token': current_api_csrf_token}
        headers = {
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': MY_NUMBERS_URL,
            'X-CSRF-TOKEN': current_api_csrf_token,
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': session.headers['User-Agent']
        }
        list_response = session.post(GET_NUMBER_LIST_API_URL, data=payload, headers=headers)
        list_response.raise_for_status()
        numbers_data = list_response.json()

        if numbers_data and isinstance(numbers_data, list):
            number_list_str = "\n".join([f"`{item.get('Number', 'N/A')}`" for item in numbers_data])
            message_text = f"**New Asset Package Acquired: {range_name}**\n\n_{len(numbers_data)} items available:_\n{number_list_str}"
            send_telegram_message(GROUP_CHAT_ID_FOR_LISTS, message_text)
    except Exception as e:
        print(f"[!] Error getting full number list: {e}")

# =================================================================================
# --- Real-time OTP Fetcher for Acquired Number ---
# =================================================================================

def realtime_otp_fetcher(session, phone_number_to_watch, acquired_range_name):
    print(f"\n--- Real-time OTP Fetcher for {phone_number_to_watch} (Range: {acquired_range_name}) ---")
    send_telegram_message(DM_CHAT_ID,
                          f"👀 *Real-time OTP Watch*\n\nMonitoring for a code on acquired number:\n`{phone_number_to_watch}` (Range: `{acquired_range_name}`)\nThis will continue until you stop the script (Ctrl+C).",
                          is_operational=True)

    while not sms_getter_stop_event.is_set():
        try:
            received_page_response = session.get(RECEIVED_SMS_PAGE_URL)
            received_page_response.raise_for_status()
            soup_received_page = BeautifulSoup(received_page_response.text, 'html.parser')

            current_otp_csrf_token = None
            new_csrf_token_tag = soup_received_page.find('meta', {'name': 'csrf-token'})
            if new_csrf_token_tag:
                current_otp_csrf_token = new_csrf_token_tag['content']
            else:
                hidden_token_input = soup_received_page.find('input', {'name': '_token'})
                if hidden_token_input:
                    current_otp_csrf_token = hidden_token_input['value']

            if not current_otp_csrf_token:
                raise Exception("Could not find CSRF token on /portal/sms/received page for OTP fetcher.")

            headers_post = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Accept': 'text/html, */*; q=0.01',
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': RECEIVED_SMS_PAGE_URL,
                'User-Agent': session.headers['User-Agent']
            }

            payload_ranges_initial = {'_token': current_otp_csrf_token}
            response_ranges_page = session.post(GET_SMS_RANGES_URL, data=payload_ranges_initial, headers=headers_post)
            response_ranges_page.raise_for_status()

            payload_numbers_in_range = {
                '_token': current_otp_csrf_token,
                'start': '',
                'end': '',
                'range': acquired_range_name
            }
            response_numbers_in_range = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload_numbers_in_range, headers=headers_post)
            response_numbers_in_range.raise_for_status()
            soup_numbers = BeautifulSoup(response_numbers_in_range.text, 'html.parser')

            target_number_div = None
            for div_tag in soup_numbers.find_all('div', onclick=True):
                onclick_value = div_tag.get('onclick', '')
                match = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)','(\d+)'\)", onclick_value)
                if match and match.group(1) == phone_number_to_watch:
                    target_number_div = div_tag
                    break

            if not target_number_div:
                print(f"[*] Number {phone_number_to_watch} not visible yet in OTP fetcher. Retrying in 10s...")
                time.sleep(10)
                continue

            onclick_match = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)','(\d+)'\)", target_number_div['onclick'])
            if not onclick_match:
                print(f"[!] Could not parse onclick for {phone_number_to_watch}. Retrying in 10s...")
                time.sleep(10)
                continue

            extracted_number_id = onclick_match.group(1)
            extracted_id_number = onclick_match.group(2)

            payload_sms_messages = {
                '_token': current_otp_csrf_token,
                'start': '',
                'end': '',
                'Number': extracted_number_id,
                'Range': acquired_range_name
            }
            response_sms_messages = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload_sms_messages, headers=headers_post)
            response_sms_messages.raise_for_status()
            soup_messages = BeautifulSoup(response_sms_messages.text, 'html.parser')

            message_text_div = soup_messages.find('div', class_='Message')
            whatsapp_code = None
            if message_text_div:
                message_content = message_text_div.get_text(strip=True)
                print(f"[*] OTP Fetcher Message content: {message_content}")
                whatsapp_code = extract_otp_from_text(message_content)

            if whatsapp_code:
                print(f"\n[SUCCESS] OTP Intercepted: {whatsapp_code}")
                notification_text = f"✅ *OTP Acquired! (Real-time Fetch)*\n\n*Number:* `{phone_number_to_watch}`\n*OTP:* `{whatsapp_code}`"
                send_telegram_message(DM_CHAT_ID, notification_text, is_operational=True)
                # Update OTP cache for Telegram listener
                with otp_cache_lock:
                    otp_cache[phone_number_to_watch] = whatsapp_code
                return True
            else:
                print(f"[*] OTP not found yet for {phone_number_to_watch}. Retrying in 10s...")

            time.sleep(10)

        except requests.exceptions.RequestException as req_e:
            print(f"[!] Network error during OTP fetch: {req_e}")
            send_telegram_message(DM_CHAT_ID, f"⚠️ *Network Error (OTP Fetch)*\n\nCould not fetch OTP for `{phone_number_to_watch}`: `{req_e}`. Retrying in 30s.", is_operational=True)
            time.sleep(30)
        except Exception as e:
            print(f"[!] General error during OTP fetch: {e}")
            send_telegram_message(DM_CHAT_ID, f"❌ *OTP Fetch Error*\n\nError fetching OTP for `{phone_number_to_watch}`: `{e}`. Retrying in 30s.", is_operational=True)
            time.sleep(30)

# =================================================================================
# --- Account Cleanup Prompt ---
# =================================================================================

def prompt_account_cleanup(session):
    send_telegram_message(DM_CHAT_ID, "Do you want to perform account cleanup? Reply with 'y' or 'n'.")

    while True:
        answer = input("Cleanup? (y/n): ").strip().lower()
        if answer == 'y':
            success = clear_all_existing_numbers(session)
            if success:
                send_telegram_message(DM_CHAT_ID, "✅ Account cleanup completed.", is_operational=True)
            else:
                send_telegram_message(DM_CHAT_ID, "No numbers to clean or cleanup failed.", is_operational=True)
            break
        elif answer == 'n':
            send_telegram_message(DM_CHAT_ID, "Account cleanup skipped as per your choice.", is_operational=True)
            break
        else:
            print("Please reply with 'y' or 'n'.")

def clear_all_existing_numbers(session):
    global api_csrf_token
    print("\n[*] Performing account cleanup...")
    try:
        page_response = session.get(TEST_NUMBERS_PAGE_URL)
        page_response.raise_for_status()
        soup = BeautifulSoup(page_response.text, 'html.parser')
        token = soup.find('meta', {'name': 'csrf-token'})
        if not token:
            print("[!] Could not find CSRF token for cleanup. Skipping cleanup.")
            return False
        api_csrf_token = token['content']

        headers = {
            'Accept': '*/*',
            'X-CSRF-TOKEN': api_csrf_token,
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': MY_NUMBERS_URL
        }
        response = session.post(REMOVE_ALL_NUMBERS_API_URL, headers=headers)
        response.raise_for_status()

        if "NumberDone" in response.text:
            print("[SUCCESS] Account cleanup complete.")
            return True
        else:
            print("[*] No existing numbers to clean up.")
            return False
    except Exception as e:
        print(f"[!] Could not perform cleanup: {e}")
        return False

# =================================================================================
# --- Real-time SMS Polling (Passive SMS Getter) ---
# =================================================================================

def get_polling_csrf_token(session):
    try:
        response = session.get(RECEIVED_SMS_PAGE_URL)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if token_tag:
            return token_tag['content']

        hidden_token_input = soup.find('input', {'name': '_token'})
        if hidden_token_input:
            return hidden_token_input['value']

        raise Exception("CSRF token not found on /portal/sms/received page.")
    except Exception as e:
        print(f"[!] Error getting polling CSRF token: {e}")
        return None

def _fetch_sms_ranges(session, token, headers):
    payload_ranges = {'_token': token}
    response_ranges = session.post(GET_SMS_RANGES_URL, data=payload_ranges, headers=headers)
    response_ranges.raise_for_status()
    soup_ranges = BeautifulSoup(response_ranges.text, 'html.parser')

    range_info_list = []
    for item_div in soup_ranges.find_all('div', class_='item'):
        card_body = item_div.find('div', class_='card-body')
        if card_body and 'onclick' in card_body.attrs:
            onclick_value = card_body['onclick']
            match = re.search(r"getDetials\('([^']+)'\)", onclick_value)
            if match:
                range_name = match.group(1)
                range_info_list.append(range_name)
    return range_info_list

def _fetch_numbers_in_range(session, token, headers, range_name):
    payload_numbers = {
        '_token': token,
        'start': '', 'end': '',
        'range': range_name
    }
    response_numbers = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload_numbers, headers=headers)
    response_numbers.raise_for_status()
    soup_numbers = BeautifulSoup(response_numbers.text, 'html.parser')

    numbers_list = []
    for number_div_with_onclick in soup_numbers.find_all('div', onclick=True):
        onclick_value = number_div_with_onclick['onclick']
        number_match = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)','(\d+)'\)", onclick_value)
        if number_match:
            phone_number = number_match.group(1)
            numbers_list.append(phone_number)
    return numbers_list

def _fetch_sms_message_content(session, token, headers, phone_number, range_name):
    payload_messages = {
        '_token': token,
        'start': '', 'end': '',
        'Number': phone_number,
        'Range': range_name
    }
    response_messages = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload_messages, headers=headers)
    response_messages.raise_for_status()
    soup_messages = BeautifulSoup(response_messages.text, 'html.parser')

    message_content_p = soup_messages.find('p', class_='mb-0 pb-0')
    cli_span = soup_messages.find('span', class_='badge-soft-warning', string='CLI')

    sender_cli = cli_span.find_next_sibling(string=True).strip() if cli_span and cli_span.find_next_sibling(string=True) else "N/A"
    message_content = message_content_p.get_text(strip=True) if message_content_p else ""

    return sender_cli, message_content

def start_realtime_sms_getter_polling(session):
    print("\n[*] Starting Real-time SMS Getter (Polling) monitor...")
    send_telegram_message(DM_CHAT_ID,
                          "📡 *SMS Getter Online*\n\nStarting to poll for new received SMS messages.", is_operational=True)

    polling_interval = 5

    while not sms_getter_stop_event.is_set():
        try:
            current_polling_csrf_token = get_polling_csrf_token(session)
            if not current_polling_csrf_token:
                print("[!] Could not get a fresh CSRF token for polling. Retrying in 30s.")
                time.sleep(30)
                continue

            headers_post = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Accept': 'text/html, */*; q=0.01',
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': RECEIVED_SMS_PAGE_URL,
                'User-Agent': session.headers['User-Agent']
            }

            print(f"[*] Polling cycle initiated...")

            range_info_list = _fetch_sms_ranges(session, current_polling_csrf_token, headers_post)

            if not range_info_list:
                print("[*] No SMS ranges found. Retrying...")
                time.sleep(polling_interval)
                continue

            for range_name in range_info_list:
                if sms_getter_stop_event.is_set():
                    break

                numbers_list = _fetch_numbers_in_range(session, current_polling_csrf_token, headers_post, range_name)
                if not numbers_list:
                    print(f"[*] No numbers found for range: {range_name}. Skipping...")
                    continue

                for phone_number in numbers_list:
                    if sms_getter_stop_event.is_set():
                        break

                    sender_cli, message_content = _fetch_sms_message_content(session, current_polling_csrf_token, headers_post, phone_number, range_name)

                    if message_content:
                        # Assume current time (or parse real sent time if available)
                        message_time_obj = datetime.utcnow()
                        process_and_report_sms(phone_number, sender_cli, message_content, message_time_obj)
                    else:
                        print(f"[*] No message content for {phone_number} in range {range_name}. Skipping.")

            print(f"[*] Polling cycle complete. Next cycle in {polling_interval} seconds.")
            time.sleep(polling_interval)

        except requests.exceptions.RequestException as req_e:
            print(f"[!] Network error during SMS polling: {req_e}")
            send_telegram_message(DM_CHAT_ID, f"❌ *Polling Error*\n\nNetwork issue during SMS fetching: `{req_e}`. Retrying in 30 seconds.", is_operational=True)
            time.sleep(30)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in SMS polling loop: {e}")
            send_telegram_message(DM_CHAT_ID, f"❌ *Polling Error*\n\nUnexpected error during SMS fetching: `{e}`. Retrying in 30 seconds.", is_operational=True)
            time.sleep(30)
    print("[*] Real-time SMS Getter (Polling) thread gracefully stopped.")

# =================================================================================
# --- Graceful Shutdown Handler ---
# =================================================================================

def remove_all_numbers_on_exit(signum, frame):
    print("\n\n[!!!] Shutdown signal detected (Ctrl+C). Initiating cleanup sequence.")
    send_telegram_message(DM_CHAT_ID, "🛑 *Shutdown Signal Detected*\n\nAttempting graceful shutdown...", is_operational=True)

    if not current_session:
        sys.exit(1)

    sms_getter_stop_event.set()
    time.sleep(2)  # Give threads time to stop

    if clear_all_existing_numbers(current_session):
        send_telegram_message(DM_CHAT_ID, "✅ *Shutdown Complete*\n\nAll temporary numbers removed. Bot is offline.", is_operational=True)
    else:
        send_telegram_message(DM_CHAT_ID, "✅ *Shutdown Complete*\n\nBot is offline (no numbers to remove or cleanup failed).", is_operational=True)

    print("[*] Exiting now.")
    sys.exit(0)

# =================================================================================
# --- Main Entrypoint ---
# =================================================================================

def main():
    global current_session
    signal.signal(signal.SIGINT, remove_all_numbers_on_exit)

    if MAGIC_RECAPTCHA_TOKEN == "09ANMylNCcYBQ6yzuazWc7Wq698PRe_i-EfYOLcTKsGj0CgpTJLSVzeIKoZ7dc13o1Vpye2GewcWkSh5yyL_6-Kx43Bd6whJI6qRXm0jRvKj2q3Q554TbZPLdi32MlflE" or "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        print("\n" + "="*70)
        print("[!!!] FATAL ERROR: You have not updated the MAGIC_RECAPTCHA_TOKEN.")
        print("      Please follow the instructions in the script to get a new one.")
        print("="*70)
        send_telegram_message(DM_CHAT_ID, "❌ *Bot Startup Failed*\n\n`MAGIC_RECAPTCHA_TOKEN` is missing or invalid. Please update it.", is_operational=True)
        return

    send_telegram_message(DM_CHAT_ID,
                          f"🚀 FXCNUMBERS Autobot is Online 🚀\n\n"
                          "Now monitoring all active ranges in real-time. New SMS and newly added ranges will be reported here.",
                          is_operational=True)

    try:
        with requests.Session() as session:
            current_session = session
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Android 11; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0'})

            print("\n[*] Step 1: Authenticating...")
            response = session.get(LOGIN_URL)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token_login_tag = soup.find('input', {'name': '_token'})
            if not csrf_token_login_tag:
                raise Exception("Could not find CSRF token on login page for initial login.")
            csrf_token_login = csrf_token_login_tag['value']

            login_payload = {
                '_token': csrf_token_login,
                'email': EMAIL,
                'password': PASSWORD,
                'g-recaptcha-response': MAGIC_RECAPTCHA_TOKEN,
                'submit': 'Log in'
            }

            login_response = session.post(LOGIN_URL, data=login_payload, headers={'Referer': LOGIN_URL})
            login_response.raise_for_status()

            # Check if login succeeded by URL and page content
            if "login" not in login_response.url and "Logout" in login_response.text:
                print("[SUCCESS] Authentication complete!")
                send_telegram_message(DM_CHAT_ID, "🔐 *Authentication Successful*\n\nSession established.", is_operational=True)

                # Prompt admin for account cleanup instead of auto cleanup
                prompt_account_cleanup(session)

                # Start Telegram listener thread first (so it can respond to commands)
                telegram_listener_thread = threading.Thread(target=telegram_listener_task, args=(session,), daemon=True)
                telegram_listener_thread.start()

                # Start SMS getter thread
                sms_getter_thread = threading.Thread(target=start_realtime_sms_getter_polling, args=(session,), daemon=True)
                sms_getter_thread.start()

                print("\n[SUCCESS] Bot is fully operational.")
                print("   > Telegram Listener running in background.")
                print("   > Real-time SMS Getter running in background.")
                print("   > Use /start1 in group (admin only) to start acquisition prompt.")
                print("   > Use /next to get next batch (admin only).")
                print("   > Use /stop to stop the bot (admin only).")

                # Keep main thread alive to keep daemon threads running
                while True:
                    time.sleep(1)

            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check credentials or recaptcha token.")
                send_telegram_message(DM_CHAT_ID, "❌ *Authentication Failed*\n\nLogin rejected. Update `MAGIC_RECAPTCHA_TOKEN` or check credentials.", is_operational=True)

    except Exception as e:
        print(f"[!!!] Critical startup error: {e}")
        send_telegram_message(DM_CHAT_ID, f"❌ *Bot Startup Error*\n\nCritical error: `{e}`. Bot shutting down.", is_operational=True)


if __name__ == "__main__":
    main()
