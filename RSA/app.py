import random
import time
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from markupsafe import Markup
import tracemalloc
import json
import base64
import math

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

# Modify the Hybrid Chaotic Key Generation to handle integer seed
def hybrid_chaotic_key(seed, iterations=20):
    """ Generates a key by combining the Logistic and Tent maps """
    
    # Convert seed to a value between 0 and 1 by normalizing
    seed = (seed % 100) / 100  # Normalize seed to a value between 0 and 1
    
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

def log_history(encryption_method, encrypted_credit_card, encrypted_expiry_date, encrypted_cvc, decrypted_data,
                encryption_time, decryption_time, total_execution_time, encryption_memory, decryption_memory, generated_key):
    # Initialize session history if it's not present
    if 'history' not in session:
        session['history'] = []
    
    # Convert the generated key to base64 for storage (to make it human-readable)
    base64_generated_key = base64.b64encode(generated_key).decode('utf-8')

    # Calculate throughput and entropy for both encrypted and decrypted data
    encryption_throughput = calculate_throughput(len(encrypted_credit_card), encryption_time)
    decryption_throughput = calculate_throughput(len(decrypted_data), decryption_time)
    
    # Calculate entropy for encrypted data
    encrypted_entropy = calculate_entropy(encrypted_credit_card)
    decrypted_entropy = calculate_entropy(decrypted_data)
    
    # Append to history
    session['history'].append({
        'encryption_method': encryption_method,
        'encrypted_credit_card': base64.b64encode(encrypted_credit_card).decode('utf-8'),  # Encrypted credit card
        'encrypted_expiry_date': base64.b64encode(encrypted_expiry_date).decode('utf-8'),  # Encrypted expiry date
        'encrypted_cvc': base64.b64encode(encrypted_cvc).decode('utf-8'),  # Encrypted CVC
        'decrypted_data': decrypted_data,  # Decrypted data
        'encryption_time': f"{encryption_time:.6f} seconds",
        'decryption_time': f"{decryption_time:.6f} seconds",
        'total_execution_time': f"{total_execution_time:.6f} seconds",
        'encryption_memory': f"{encryption_memory / 1024:.2f} KB",  # Encrypted memory in KB
        'decryption_memory': f"{decryption_memory / 1024:.2f} KB",  # Decrypted memory in KB
        'generated_key': base64_generated_key,  # Base64-encoded key
        'encryption_throughput': f"{encryption_throughput:.2f} KB/sec",  # Encryption throughput
        'decryption_throughput': f"{decryption_throughput:.2f} KB/sec",  # Decryption throughput
        'encrypted_entropy': f"{encrypted_entropy:.6f}",  # Encrypted entropy
        'decrypted_entropy': f"{decrypted_entropy:.6f}",  # Decrypted entropy
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')  # Timestamp for the transaction
    })
    session.modified = True



# Convert bytes to binary string
def bytes_to_bin(data):
    """Convert byte data to a binary string."""
    return ''.join(format(byte, '08b') for byte in data)

# Frequency Test (Monobit test)
def frequency_test(bin_data):
    """Perform frequency (monobit) test for randomness"""
    ones = bin_data.count('1')
    zeros = len(bin_data) - ones
    expected = len(bin_data) / 2
    return abs(ones - expected) < (len(bin_data) ** 0.5)

# Runs Test
def runs_test(bin_data):
    """Perform runs test (count sequences of 1s or 0s)"""
    runs = 0
    current_char = bin_data[0]
    for char in bin_data[1:]:
        if char != current_char:
            runs += 1
            current_char = char
    return runs > len(bin_data) // 2  # The number of runs should not be too low

# Autocorrelation Test
def autocorrelation_test(bin_data):
    """Perform autocorrelation test (checks for periodicity)"""
    n = len(bin_data)
    count = sum(1 for i in range(n) if bin_data[i] == bin_data[(i + n//2) % n])
    return count > n // 2  # Should not have periodicity

# Key Generation Test
def test_key_generation_randomness(key, method):
    """Test the randomness of the generated key"""
    bin_key = bytes_to_bin(key)
    
    frequency_result = frequency_test(bin_key)
    runs_result = runs_test(bin_key)
    autocorrelation_result = autocorrelation_test(bin_key)

    return {
        'method': method,
        'frequency_test': frequency_result,
        'runs_test': runs_result,
        'autocorrelation_test': autocorrelation_result
    }

# Function to calculate throughput in KB/sec
def calculate_throughput(data_size, process_time):
    """ Calculate throughput in KB per second """
    if process_time > 0:
        return (data_size / process_time) / 1024  # Convert from Bytes/sec to KB/sec
    return 0


# Function to calculate entropy
def calculate_entropy(data):
    """ Calculate Shannon entropy of the data """
    # Count frequency of each byte
    byte_frequencies = {}
    for byte in data:
        byte_frequencies[byte] = byte_frequencies.get(byte, 0) + 1
    
    # Calculate entropy
    data_size = len(data)
    entropy = 0
    for count in byte_frequencies.values():
        prob = count / data_size
        entropy -= prob * math.log2(prob)
    
    return entropy

# Route for home/catalog page
@app.route('/')
def index():
    return render_template('index.html', catalog=CATALOG)

@app.route('/generate_key')
def generate_key():
    return render_template('generate_key.html')

@app.route('/test_randomness', methods=['POST'])
def test_randomness():
    seed = float(request.form['seed'])  # Get seed value from form input
    encryption_method = request.form['encryption_method']  # Get selected encryption method

    if encryption_method == 'rctm':
        generated_key = rctm_key(seed)
    elif encryption_method == 'hybrid_chaotic':
        generated_key = hybrid_chaotic_key(seed)
    else:
        return "Invalid encryption method selected."

    # Run randomness tests
    randomness_results = test_key_generation_randomness(generated_key, encryption_method)

    return render_template('randomness_result.html', results=randomness_results, key=base64.b64encode(generated_key).decode())

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        address = request.form['address']
        credit_card = request.form['credit_card']
        expiry_date = request.form['expiry_date']
        cvc = request.form['cvc']
        encryption_method = request.form['encryption_method']  # Get selected encryption method
        
        # Generate secret key for encryption based on selected method (RCTM or Hybrid Chaotic)
        secret_key = random.random()  # Secret key for chaotic map generation
        
        if encryption_method == 'rctm':
            generated_key = rctm_key(secret_key)
        elif encryption_method == 'hybrid_chaotic':
            generated_key = hybrid_chaotic_key(secret_key)
        else:
            generated_key = b'\0' * 16  # Default key if no method is selected (AES requires 16-byte key)

        # Encrypt the credit card, expiry date, and CVC
        tracemalloc.start()  # Start memory tracking
        start_memory_credit_card = tracemalloc.get_traced_memory()[0]
        start_time_credit_card = time.perf_counter()
        encrypted_credit_card = aes_encrypt(credit_card, generated_key)
        encryption_end_time_credit_card = time.perf_counter()
        encryption_time_credit_card = encryption_end_time_credit_card - start_time_credit_card
        end_memory_credit_card = tracemalloc.get_traced_memory()[0]
        encryption_memory_credit_card = end_memory_credit_card - start_memory_credit_card
        tracemalloc.stop()  # Stop memory tracking

        # Measure decryption time and memory usage for credit card
        tracemalloc.start()
        start_memory_decrypt_credit_card = tracemalloc.get_traced_memory()[0]
        start_decrypt_time_credit_card = time.perf_counter()
        decrypted_credit_card = aes_decrypt(encrypted_credit_card, generated_key)
        decryption_end_time_credit_card = time.perf_counter()
        decryption_time_credit_card = decryption_end_time_credit_card - start_decrypt_time_credit_card
        end_memory_decrypt_credit_card = tracemalloc.get_traced_memory()[0]
        decryption_memory_credit_card = end_memory_decrypt_credit_card - start_memory_decrypt_credit_card
        tracemalloc.stop()

        # Measure encryption time and memory usage for expiry date
        tracemalloc.start()
        start_memory_encrypt_expiry = tracemalloc.get_traced_memory()[0]
        start_time_expiry = time.perf_counter()
        encrypted_expiry_date = aes_encrypt(expiry_date, generated_key)
        encryption_end_time_expiry = time.perf_counter()
        encryption_time_expiry = encryption_end_time_expiry - start_time_expiry
        end_memory_encrypt_expiry = tracemalloc.get_traced_memory()[0]
        encryption_memory_expiry_date = end_memory_encrypt_expiry - start_memory_encrypt_expiry
        tracemalloc.stop()

        # Measure decryption time and memory usage for expiry date
        tracemalloc.start()
        start_memory_decrypt_expiry = tracemalloc.get_traced_memory()[0]
        start_decrypt_time_expiry = time.perf_counter()
        decrypted_expiry_date = aes_decrypt(encrypted_expiry_date, generated_key)
        decryption_end_time_expiry = time.perf_counter()
        decryption_time_expiry = decryption_end_time_expiry - start_decrypt_time_expiry
        end_memory_decrypt_expiry = tracemalloc.get_traced_memory()[0]
        decryption_memory_expiry_date = end_memory_decrypt_expiry - start_memory_decrypt_expiry
        tracemalloc.stop()

        # Measure encryption time and memory usage for CVC
        tracemalloc.start()
        start_memory_encrypt_cvc = tracemalloc.get_traced_memory()[0]
        start_time_cvc = time.perf_counter()
        encrypted_cvc = aes_encrypt(cvc, generated_key)
        encryption_end_time_cvc = time.perf_counter()
        encryption_time_cvc = encryption_end_time_cvc - start_time_cvc
        end_memory_encrypt_cvc = tracemalloc.get_traced_memory()[0]
        encryption_memory_cvc = end_memory_encrypt_cvc - start_memory_encrypt_cvc
        tracemalloc.stop()

        # Measure decryption time and memory usage for CVC
        tracemalloc.start()
        start_memory_decrypt_cvc = tracemalloc.get_traced_memory()[0]
        start_decrypt_time_cvc = time.perf_counter()
        decrypted_cvc = aes_decrypt(encrypted_cvc, generated_key)
        decryption_end_time_cvc = time.perf_counter()
        decryption_time_cvc = decryption_end_time_cvc - start_decrypt_time_cvc
        end_memory_decrypt_cvc = tracemalloc.get_traced_memory()[0]
        decryption_memory_cvc = end_memory_decrypt_cvc - start_memory_decrypt_cvc
        tracemalloc.stop()

        # Calculate total execution time (sum of encryption and decryption times)
        total_execution_time = (encryption_time_credit_card + decryption_time_credit_card + 
                                encryption_time_expiry + decryption_time_expiry + 
                                encryption_time_cvc + decryption_time_cvc)
        
        # Calculate total memory used during encryption and decryption
        encryption_memories = (encryption_memory_credit_card + encryption_memory_expiry_date +
                                encryption_memory_cvc)
        decryption_memories = (decryption_memory_credit_card + decryption_memory_expiry_date +
                                decryption_memory_cvc)

        # Log the transaction including the generated key
        log_history(encryption_method, encrypted_credit_card, encrypted_expiry_date, encrypted_cvc, decrypted_credit_card,
                    encryption_time_credit_card, decryption_time_credit_card, total_execution_time, encryption_memories, decryption_memories, generated_key)

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

def calculate_average(data):
    valid_data = [x for x in data if not isinstance(x, str)]  # Remove any NaN or invalid entries
    return sum(valid_data) / len(valid_data) if valid_data else 0


# Route for performance analysis page
@app.route('/performance')
def performance():
    history = session.get('history', [])
    hybrid_chaotic_data = {
        'encryption_times': [],
        'decryption_times': [],
        'total_execution_times': [],
        'encryption_memories': [],
        'decryption_memories': [],
        'encryption_throughput': [],
        'decryption_throughput': [],
        'encrypted_entropy': [],
        'decrypted_entropy': []
    }
    rctm_data = {
        'encryption_times': [],
        'decryption_times': [],
        'total_execution_times': [],
        'encryption_memories': [],
        'decryption_memories': [],
        'encryption_throughput': [],
        'decryption_throughput': [],
        'encrypted_entropy': [],
        'decrypted_entropy': []
    }

    for record in history:
        data_container = hybrid_chaotic_data if record['encryption_method'] == 'hybrid_chaotic' else rctm_data
        data_container['encryption_times'].append(float(record['encryption_time'].split()[0]))
        data_container['decryption_times'].append(float(record['decryption_time'].split()[0]))
        data_container['total_execution_times'].append(float(record['total_execution_time'].split()[0]))
        data_container['encryption_memories'].append(float(record['encryption_memory'].split()[0]))
        data_container['decryption_memories'].append(float(record['decryption_memory'].split()[0]))
        data_container['encryption_throughput'].append(float(record['encryption_throughput'].split()[0]))
        data_container['decryption_throughput'].append(float(record['decryption_throughput'].split()[0]))
        data_container['encrypted_entropy'].append(float(record['encrypted_entropy']))
        data_container['decrypted_entropy'].append(float(record['decrypted_entropy']))

    performance_data = {'hybrid_chaotic': hybrid_chaotic_data, 'rctm': rctm_data}

    return render_template('performance.html', performance_data=performance_data)


@app.route('/clear_history')
def clear_history():
    session.clear()
    return redirect(url_for('index')) 


if __name__ == '__main__':
    app.run(debug=True)