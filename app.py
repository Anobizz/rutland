from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
import random, logging, qrcode, io, os, json, hashlib, re
from datetime import datetime
from functools import wraps

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

# Dummy card database
DUMMY_CARDS = {
    "4114755393849011": {"expiry": "0926", "cvv": "363", "auth": "1942", "type": "POS-101.1"},
    "4000123412341234": {"expiry": "1126", "cvv": "123", "auth": "4021", "type": "POS-101.1"},
    "4117459374038454": {"expiry": "1026", "cvv": "258", "auth": "384726", "type": "POS-101.4"},
    "4123456789012345": {"expiry": "0826", "cvv": "852", "auth": "495128", "type": "POS-101.4"},
    "5454957994741066": {"expiry": "1126", "cvv": "746", "auth": "627192", "type": "POS-101.6"},
    "6011000990131077": {"expiry": "0825", "cvv": "330", "auth": "8765", "type": "POS-101.7"},
    "3782822463101088": {"expiry": "1226", "cvv": "1059", "auth": "0000", "type": "POS-101.8"},
    "3530760473041099": {"expiry": "0326", "cvv": "244", "auth": "712398", "type": "POS-201.1"},
    "4114938274651920": {"expiry": "0926", "cvv": "463", "auth": "3127", "type": "POS-101.1"},
    "4001948263728191": {"expiry": "1026", "cvv": "291", "auth": "574802", "type": "POS-101.4"},
    "6011329481720394": {"expiry": "0825", "cvv": "310", "auth": "8891", "type": "POS-101.7"},
    "378282246310106":  {"expiry": "1226", "cvv": "1439", "auth": "0000", "type": "POS-101.8"},
    "3531540982734612": {"expiry": "0326", "cvv": "284", "auth": "914728", "type": "POS-201.1"},
    "5456038291736482": {"expiry": "1126", "cvv": "762", "auth": "695321", "type": "POS-201.3"},
    "4118729301748291": {"expiry": "1026", "cvv": "249", "auth": "417263", "type": "POS-201.5"}
}

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

FIELD_39_RESPONSES = {
    "05": "Do Not Honor",
    "14": "Terminal unable to resolve encrypted session state. Contact card issuer",
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative",
    "92": "Invalid Terminal Protocol"
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
            return redirect(url_for('rejected', code="92", reason=FIELD_39_RESPONSES["92"]))
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected]
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


        return redirect(url_for('card'))  # ✅ Final return

    return render_template('payout.html')  # ✅ GET handler
#
#@app.route('/card', methods=['GET', 'POST'])
#@login_required
#def card():
    #if request.method == 'POST':
        #pan = request.form['pan'].replace(" ", "")
        #exp = request.form['expiry'].replace("/", "")
        #cvv = request.form['cvv']
        #session.update({'pan': pan, 'exp': exp, 'cvv': cvv})
        #card = DUMMY_CARDS.get(pan)
        #if card:
            #if exp != card['expiry']:
                #return redirect(url_for('rejected', code="54", reason=FIELD_39_RESPONSES["54"]))
            #if cvv != card['cvv']:
                #return redirect(url_for('rejected', code="82", reason=FIELD_39_RESPONSES["82"]))
        #return redirect(url_for('auth'))
    #return render_template('card.html')
#
#@app.route('/auth', methods=['GET', 'POST'])
#@login_required
#def auth():
    #pan = session.get('pan')
    #card = DUMMY_CARDS.get(pan)
    #expected_length = session.get('code_length', 6)
    #if request.method == 'POST':
        #code = request.form.get('auth')
        #if not card:
            #return redirect(url_for('rejected', code="14", reason=FIELD_39_RESPONSES["14"]))
        #if len(code) != expected_length:
            #return render_template('auth.html', warning=f"Code must be {expected_length} digits.")
        #if code == card['auth']:
            #txn_id = f"TXN{random.randint(100000, 999999)}"
            #arn = f"ARN{random.randint(100000000000, 999999999999)}"
            #timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            #field39 = "00"
            #session.update({
                #"txn_id": txn_id,
                #"arn": arn,
                #"timestamp": timestamp,
                #"field39": field39
            #})
            #return redirect(url_for('success'))
        #return redirect(url_for('rejected', code="05", reason=FIELD_39_RESPONSES["05"]))
    #return render_template('auth.html')
#

@app.route('/card', methods=['GET', 'POST'])
@login_required
def card():

    # =============================
    # TEMPORARY CARD ACCEPTANCE LOGIC
    # =============================
    if request.method == 'POST':
        pan = request.form['pan'].replace(" ", "")
        exp = request.form['expiry'].replace("/", "")
        cvv = request.form['cvv']
        session.update({'pan': pan, 'exp': exp, 'cvv': cvv})

        # Card type inference for receipt
        if pan.startswith("4"):
            session['card_type'] = "VISA"
        elif pan.startswith("5"):
            session['card_type'] = "MASTERCARD"
        elif pan.startswith("3"):
            session['card_type'] = "AMEX"
        elif pan.startswith("6"):
            session['card_type'] = "DISCOVER"
        else:
            session['card_type'] = "UNKNOWN"

        return redirect(url_for('auth'))

    return render_template('card.html')



@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    expected_length = session.get('code_length', 6)

    # =============================
    # TEMPORARY UNIVERSAL SUCCESS LOGIC
    # =============================
    if request.method == 'POST':
        code = request.form.get('auth')
        if len(code) != expected_length:
            return render_template('auth.html', warning=f"Code must be {expected_length} digits.")

        txn_id = f"TXN{random.randint(100000, 999999)}"
        arn = f"ARN{random.randint(100000000000, 999999999999)}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        field39 = "00"

        session.update({
            "txn_id": txn_id,
            "arn": arn,
            "timestamp": timestamp,
            "field39": field39
        })

        return redirect(url_for('success'))

    return render_template('auth.html')


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
    if raw_amount and raw_amount.isdigit():
        amount_fmt = f"{int(raw_amount):,}.00"
    else:
        amount_fmt = "0.00"


    return render_template("receipt.html",
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan")[-4:],
        amount=amount_fmt,
        payout=session.get("payout_type"),  # <-- Fixed here
        wallet=session.get("wallet"),
        auth_code="*" * auth_digits,        # <-- Dynamic masking
        iso_field_18="5999",                # Default MCC
        iso_field_25="00",                  # POS condition
        field39="00",                       # ISO8583 Field 39
        card_type=session.get("card_type", "VISA"),
        protocol_version=protocol_version,  # <-- Clean protocol
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route('/rejected')
def rejected():
    return render_template('rejected.html',
        code=request.args.get("code"),
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

