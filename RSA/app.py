import random
import time
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session
from markupsafe import Markup
import tracemalloc
import json
import base64

# Define escapejs filter
def escapejs(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value)  # Convert Python dict or list to JSON string
    return Markup(value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\'", "\\\'").replace("\n", "\\n")
                .replace("\r", "\\r").replace("\t", "\\t"))

# Flask setup
app = Flask(__name__)
app.secret_key = 'kelompok14_secure_ecommerce'
app.jinja_env.filters['escapejs'] = escapejs

# Hybrid Chaotic Key Generation (Logistic + Tent Map)
def hybrid_chaotic_key(seed, iterations=20):
    """ Generates a key by combining the Logistic and Tent maps """
    key_sequence = []
    
    x_logistic = seed  # Initial value for the Logistic Map
    x_tent = seed      # Initial value for the Tent Map
    
    for _ in range(iterations):
        # Apply chaotic maps
        x_logistic = logistic_map(x_logistic)
        x_tent = tent_map(x_tent)
        
        # Combine maps for enhanced randomness
        combined_value = (x_logistic + x_tent) % 1
        key_sequence.append(str(int(combined_value * 1000000)))
    
    # Return a key derived from SHA-256 hash of combined sequence
    return hashlib.sha256(''.join(key_sequence).encode()).digest()  # AES expects a byte key

# RCTM Key Generation (Simple Chaotic System)
def rctm_key(seed, iterations=10):
    """ Generates a key based on a simple chaotic system (RCTM) """
    key_sequence = []
    
    x = seed  # Initial value
    r = 3.8  # Control parameter for the chaotic system
    
    for _ in range(iterations):
        # Simple chaotic update rule (could be more complex)
        x = (r * x * (1 - x)) % 1  # Logistic-like iteration
        key_sequence.append(int(x * 256))  # Scale to range [0, 255]
    
    return bytes(key_sequence[:16])  # Return the first 16 bytes for AES (128-bit key)

# Logistic Map (used in Hybrid Chaotic)
def logistic_map(x, r=3.99):
    """ Logistic Map: x_{n+1} = r * x_n * (1 - x_n) """
    return r * x * (1 - x)

# Tent Map (used in Hybrid Chaotic)
def tent_map(x, r=1.5):
    """ Tent Map: 
    x_{n+1} = r * x_n if x_n < 0.5
    x_{n+1} = r * (1 - x_n) if x_n >= 0.5
    """
    if x < 0.5:
        return r * x
    else:
        return r * (1 - x)

# Simplified AES-like Block Cipher (using XOR)
def xor_bytes(data, key):
    """ XOR the data with the key (basic encryption) """
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def aes_encrypt(plaintext, secret_key):
    """ Simplified AES-like encryption using XOR """
    key = secret_key.ljust(16, b'\0')[:16]  # Ensure key length is 16 bytes (128-bit)
    
    # Convert plaintext to bytes
    plaintext = plaintext.encode('utf-8')

    # Ensure plaintext is 16 bytes long (simple block size of 16)
    if len(plaintext) < 16:
        plaintext = plaintext.ljust(16, b'\0')  # Pad with null bytes
    elif len(plaintext) > 16:
        plaintext = plaintext[:16]  # Truncate if longer than 16 bytes

    # Apply XOR encryption
    encrypted_data = xor_bytes(plaintext, key)
    return encrypted_data

def aes_decrypt(encrypted_data, secret_key):
    """ Simplified AES-like decryption using XOR (same as encryption) """
    key = secret_key.ljust(16, b'\0')[:16]  # Ensure key length is 16 bytes (128-bit)
    
    # Decrypt by applying XOR with the same key
    decrypted_data = xor_bytes(encrypted_data, key).decode('utf-8').rstrip('\0')
    return decrypted_data

# Simplified DES-like Block Cipher (using XOR)
def des_encrypt(plaintext, secret_key):
    """ Simplified DES-like encryption using XOR """
    key = secret_key.ljust(8, b'\0')[:8]  # Ensure key length is 8 bytes (64-bit)
    
    # Convert plaintext to bytes
    plaintext = plaintext.encode('utf-8')

    # Ensure plaintext is 8 bytes long (simple block size of 8)
    if len(plaintext) < 8:
        plaintext = plaintext.ljust(8, b'\0')  # Pad with null bytes
    elif len(plaintext) > 8:
        plaintext = plaintext[:8]  # Truncate if longer than 8 bytes

    # Apply XOR encryption
    encrypted_data = xor_bytes(plaintext, key)
    return encrypted_data

def des_decrypt(encrypted_data, secret_key):
    """ Simplified DES-like decryption using XOR (same as encryption) """
    key = secret_key.ljust(8, b'\0')[:8]  # Ensure key length is 8 bytes (64-bit)
    
    # Decrypt by applying XOR with the same key
    decrypted_data = xor_bytes(encrypted_data, key).decode('utf-8').rstrip('\0')
    return decrypted_data

# Encrypt based on selected method (AES is used with the key)
def encrypt_data(plaintext, secret_key):
    return aes_encrypt(plaintext, secret_key)

# Decrypt based on selected method (AES is used with the key)
def decrypt_data(encrypted_data, secret_key):
    return aes_decrypt(encrypted_data, secret_key)

# Catalog (moved outside to be accessible in other routes)
CATALOG = [
    {'id': 1, 'name': 'Laptop', 'price': 1000, 'description': 'A high-performance laptop.', 'image': 'images/lappy.jpg'},
    {'id': 2, 'name': 'Monitor', 'price': 250, 'description': 'FHD 100% S-RGB 144 Hz Gaming Monitor.', 'image': 'images/monitor.jpg'},
    {'id': 3, 'name': 'Smartphone', 'price': 600, 'description': 'A smartphone with all the latest features.', 'image': 'images/phone.jpg'},
    {'id': 4, 'name': 'Headphones', 'price': 150, 'description': 'Noise-cancelling headphones for clear sound.', 'image': 'images/headphones.jpeg'},
    {'id': 5, 'name': 'Keyboard', 'price': 150, 'description': 'Gaming Keyboard.', 'image': 'images/keyboard.jpg'},
    {'id': 6, 'name': 'Mouse', 'price': 120, 'description': 'Gaming Mouse.', 'image': 'images/mouse.jpg'}
]

def log_history(encryption_method, encrypted_data, decrypted_data, encryption_time, decryption_time, total_execution_time, encryption_memory, decryption_memory):
    # Initialize session history if it's not present
    if 'history' not in session:
        session['history'] = []
    
    # Append a new log entry to the history
    session['history'].append({
        'encryption_method': encryption_method,
        'encrypted_data': encrypted_data,
        'decrypted_data': decrypted_data,
        'encryption_time': f"{encryption_time:.6f} seconds",
        'decryption_time': f"{decryption_time:.6f} seconds",
        'total_execution_time': f"{total_execution_time:.6f} seconds",
        'encryption_memory': f"{encryption_memory / 1024:.2f} KB",  # Convert to KB
        'decryption_memory': f"{decryption_memory / 1024:.2f} KB",  # Convert to KB
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')  # Timestamp for the transaction
    })
    # Make sure to save the updated session data
    session.modified = True

# Route for home/catalog page
@app.route('/')
def index():
    return render_template('index.html', catalog=CATALOG)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        credit_card = request.form['credit_card']
        expiry_date = request.form['expiry_date']
        cvc = request.form['cvc']
        encryption_method = request.form['encryption_method']  # Get selected encryption method
        
        # Secret Key for Hybrid Chaotic or RCTM key generation
        secret_key = random.random()  # Secret key for chaotic map generation
        
        # Generate key using the selected method (RCTM or Hybrid Chaotic)
        if encryption_method == 'rctm':
            generated_key = rctm_key(secret_key)
        elif encryption_method == 'hybrid_chaotic':
            generated_key = hybrid_chaotic_key(secret_key)
        else:
            generated_key = b'\0' * 16  # Default key if no method is selected (AES requires 16-byte key)


        tracemalloc.start()  # Start memory tracking
        start_memory_credit_card = tracemalloc.get_traced_memory()[0]
        start_time_credit_card = time.perf_counter()
        encrypted_credit_card = encrypt_data(credit_card, generated_key)
        encryption_end_time_credit_card = time.perf_counter()
        encryption_time_credit_card = encryption_end_time_credit_card - start_time_credit_card
        end_memory_credit_card = tracemalloc.get_traced_memory()[0]
        encryption_memory_credit_card = end_memory_credit_card - start_memory_credit_card
        tracemalloc.stop()  # Stop memory tracking

        # Measure decryption time and memory usage for credit card
        tracemalloc.start()
        start_memory_decrypt_credit_card = tracemalloc.get_traced_memory()[0]
        start_decrypt_time_credit_card = time.perf_counter()
        decrypted_credit_card = decrypt_data(encrypted_credit_card, generated_key)
        decryption_end_time_credit_card = time.perf_counter()
        decryption_time_credit_card = decryption_end_time_credit_card - start_decrypt_time_credit_card
        end_memory_decrypt_credit_card = tracemalloc.get_traced_memory()[0]
        decryption_memory_credit_card = end_memory_decrypt_credit_card - start_memory_decrypt_credit_card
        tracemalloc.stop()

        # Measure encryption time and memory usage for expiry date
        tracemalloc.start()
        start_memory_encrypt_expiry = tracemalloc.get_traced_memory()[0]
        start_time_expiry = time.perf_counter()
        encrypted_expiry_date = encrypt_data(expiry_date, generated_key)
        encryption_end_time_expiry = time.perf_counter()
        encryption_time_expiry = encryption_end_time_expiry - start_time_expiry
        end_memory_encrypt_expiry = tracemalloc.get_traced_memory()[0]
        encryption_memory_encrypt_expiry = end_memory_encrypt_expiry - start_memory_encrypt_expiry
        tracemalloc.stop()

        # Measure decryption time and memory usage for expiry date
        tracemalloc.start()
        start_memory_decrypt_expiry = tracemalloc.get_traced_memory()[0]
        start_decrypt_time_expiry = time.perf_counter()
        decrypted_expiry_date = decrypt_data(encrypted_expiry_date, generated_key)
        decryption_end_time_expiry = time.perf_counter()
        decryption_time_expiry = decryption_end_time_expiry - start_decrypt_time_expiry
        end_memory_decrypt_expiry = tracemalloc.get_traced_memory()[0]
        decryption_memory_decrypt_expiry = end_memory_decrypt_expiry - start_memory_decrypt_expiry
        tracemalloc.stop()

        # Measure encryption time and memory usage for CVC
        tracemalloc.start()
        start_memory_encrypt_cvc = tracemalloc.get_traced_memory()[0]
        start_time_cvc = time.perf_counter()
        encrypted_cvc = encrypt_data(cvc, generated_key)
        encryption_end_time_cvc = time.perf_counter()
        encryption_time_cvc = encryption_end_time_cvc - start_time_cvc
        end_memory_encrypt_cvc = tracemalloc.get_traced_memory()[0]
        encryption_memory_encrypt_cvc = end_memory_encrypt_cvc - start_memory_encrypt_cvc
        tracemalloc.stop()

        # Measure decryption time and memory usage for CVC
        tracemalloc.start()
        start_memory_decrypt_cvc = tracemalloc.get_traced_memory()[0]
        start_decrypt_time_cvc = time.perf_counter()
        decrypted_cvc = decrypt_data(encrypted_cvc, generated_key)
        decryption_end_time_cvc = time.perf_counter()
        decryption_time_cvc = decryption_end_time_cvc - start_decrypt_time_cvc
        end_memory_decrypt_cvc = tracemalloc.get_traced_memory()[0]
        decryption_memory_decrypt_cvc = end_memory_decrypt_cvc - start_memory_decrypt_cvc
        tracemalloc.stop()

        # Calculate total execution time
        total_execution_time = (encryption_time_credit_card + decryption_time_credit_card + 
                                encryption_time_expiry + decryption_time_expiry + 
                                encryption_time_cvc + decryption_time_cvc)
        
        encryption_memories = (encryption_memory_credit_card + encryption_memory_encrypt_expiry +
                                encryption_memory_encrypt_cvc)
        decryption_memories = (decryption_memory_credit_card + decryption_memory_decrypt_expiry +
                                decryption_memory_decrypt_cvc)

        # Log transaction history for credit card only (one row per transaction)
        log_history(encryption_method, encrypted_credit_card, decrypted_credit_card, encryption_time_credit_card, decryption_time_credit_card, 
                    total_execution_time, encryption_memories, decryption_memories)

        return render_template('checkout.html', 
            encrypted_payment={
                'credit_card': encrypted_credit_card,
                'expiry_date': encrypted_expiry_date,
                'cvc': encrypted_cvc
            },
            decrypted_payment={
                'credit_card': decrypted_credit_card,
                'expiry_date': decrypted_expiry_date,
                'cvc': decrypted_cvc
            },
            name=name,
            address=address,
            history=session.get('history', [])  # Pass the history to the template
        )
    
    return render_template('checkout.html')

# Add to cart functionality
@app.route('/cart')
def cart():
    cart_items = session.get('cart', [])
    total = sum(item['price'] for item in cart_items)
    return render_template('cart.html', cart=cart_items, total=total)

@app.route('/add_to_cart/<int:item_id>', methods=['POST'])
def add_to_cart(item_id):
    cart = session.get('cart', [])
    item = next((x for x in CATALOG if x['id'] == item_id), None)
    if item:
        cart.append(item)
        session['cart'] = cart
    return '', 204

@app.route('/cart_count')
def cart_count():
    cart = session.get('cart', [])
    return {'count': len(cart)}

@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    cart = session.get('cart', [])
    if item_id < len(cart):
        cart.pop(item_id)
        session['cart'] = cart
    return redirect(url_for('cart'))

# Function to encode bytes to base64 string
def encode_bytes_data(data):
    if isinstance(data, bytes):
        return base64.b64encode(data).decode('utf-8')  # Encode bytes as a base64 string
    return data  # Return non-bytes data as is

@app.route('/performance')
def performance():
    # Extract history from session
    history = session.get('history', [])
    
    # Initialize data containers for the two encryption methods
    hybrid_chaotic_data = {
        'encryption_times': [],
        'decryption_times': [],
        'total_execution_times': [],
        'encryption_memories': [],
        'decryption_memories': [],
        'encrypted_data': [],
        'decrypted_data': [],
        'timestamps': []
    }
    rctm_data = {
        'encryption_times': [],
        'decryption_times': [],
        'total_execution_times': [],
        'encryption_memories': [],
        'decryption_memories': [],
        'encrypted_data': [],
        'decrypted_data': [],
        'timestamps': []
    }

    # Process history to separate data based on encryption method
    for record in history:
        data_container = hybrid_chaotic_data if record['encryption_method'] == 'hybrid_chaotic' else rctm_data
        
        # Append relevant fields to the corresponding container
        data_container['encryption_times'].append(float(record['encryption_time'].split()[0]))
        data_container['decryption_times'].append(float(record['decryption_time'].split()[0]))
        data_container['total_execution_times'].append(float(record['total_execution_time'].split()[0]))
        data_container['encryption_memories'].append(float(record['encryption_memory'].split()[0]))
        data_container['decryption_memories'].append(float(record['decryption_memory'].split()[0]))
        
        # Convert encrypted and decrypted data to base64
        data_container['encrypted_data'].append(encode_bytes_data(record['encrypted_data']))
        data_container['decrypted_data'].append(encode_bytes_data(record['decrypted_data']))
        
        data_container['timestamps'].append(record['timestamp'])

    # Prepare data for rendering
    performance_data = {
        'hybrid_chaotic': hybrid_chaotic_data,
        'rctm': rctm_data
    }

    return render_template('performance.html', performance_data=performance_data)

@app.route('/clear_history')
def clear_history():
    session.clear()
    return redirect(url_for('index')) 


if __name__ == '__main__':
    app.run(debug=True)
