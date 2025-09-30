# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import time
import threading
import psutil
import random
import hashlib
import jwt
import datetime
from functools import wraps
from datetime import datetime, timedelta
from collections import deque
import logging
import os
import sys
import psycopg
from psycopg.rows import dict_row

def get_db_connection():
    """Get PostgreSQL database connection"""
    try:
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url:
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            conn = psycopg.connect(
                database_url,
                row_factory=dict_row
            )
            return conn
        else:
            # Fallback for local development
            conn = psycopg.connect(
                "host=localhost dbname=cybersecurity user=postgres password=password",
                row_factory=dict_row
            )
            return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'angelsuccess-cybersecurity-2025-secret-key')
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'angelsuccess-jwt-secret-2025')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('CyberSecurityAI')

# Enhanced Real-time data structures
real_time_data = {
    'network_traffic': deque(maxlen=200),
    'threat_events': deque(maxlen=100),
    'system_metrics': deque(maxlen=120),
    'ai_predictions': deque(maxlen=50),
    'active_connections': deque(maxlen=40),
    'news_feed': deque(maxlen=30),
    'performance_metrics': deque(maxlen=100),
    'ai_training_data': deque(maxlen=200),
    'optimization_logs': deque(maxlen=50),
    'threat_intelligence': deque(maxlen=100)
}

# Enhanced System state with new features
system_state = {
    'total_threats': 0,
    'active_incidents': 0,
    'system_health': 95,
    'ai_models': {
        'status': 'operational', 
        'accuracy': 0.96,
        'supervised_accuracy': 0.94,
        'unsupervised_accuracy': 0.89,
        'ensemble_accuracy': 0.97,
        'training_status': 'active',
        'models': ['Isolation Forest', 'Autoencoder', 'XGBoost', 'LSTM', 'Random Forest', 'SVM']
    },
    'security_level': 'HIGH',
    'false_positives': 0,
    'optimization_score': 87,
    'performance_boost': 45,
    'threat_prevention_rate': 92.5,
    'response_time': 12,
    'network_latency': 28,
    'ai_confidence': 94.2,
    'encryption_strength': 256,
    'firewall_rules': 1247,
    'vulnerabilities_patched': 342,
    'data_processed_tb': 12.7,
    'threat_intelligence_sources': 15
}

# PostgreSQL connection function with psycopg3
def get_db_connection():
    """Get PostgreSQL database connection"""
    try:
        # Railway provides DATABASE_URL environment variable
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url:
            # Parse the database URL
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            conn = psycopg.connect(
                database_url,
                row_factory=dict_row
            )
            return conn
        else:
            # Fallback for local development
            conn = psycopg.connect(
                "host=localhost dbname=cybersecurity user=postgres password=password",
                row_factory=dict_row
            )
            return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def init_db():
    """Initialize PostgreSQL database"""
    conn = get_db_connection()
    if not conn:
        logger.error("Failed to connect to database")
        return
    
    try:
        # Create users table
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    plan TEXT DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Check if test user exists
            cur.execute('SELECT COUNT(*) FROM users WHERE email = %s', ('test@example.com',))
            user_count = cur.fetchone()['count']
            
            if user_count == 0:
                hashed_password = hash_password('password123')
                cur.execute(
                    'INSERT INTO users (full_name, email, password) VALUES (%s, %s, %s)',
                    ('Test User', 'test@example.com', hashed_password)
                )
                print("✅ Created default test user: test@example.com / password123")
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        if conn:
            conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token or not verify_token(token):
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def login_required_redirect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token or not verify_token(token):
            return redirect(url_for('auth_page'))
        return f(*args, **kwargs)
    return decorated_function

class AdvancedRealTimeDataEngine:
    """Enhanced real-time data processing engine with AI features"""
    
    def __init__(self):
        self.connected_clients = set()
        self.threat_history = []
        self.performance_metrics = []
        self.ai_training_cycles = 0
        self.optimization_cycles = 0
        self.false_positive_reduction = 0.65
        
    def update_network_stats(self):
        """Update comprehensive network statistics"""
        try:
            net_io = psutil.net_io_counters()
            timestamp = datetime.now()
            
            data_point = {
                'timestamp': timestamp.isoformat(),
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_per_sec': (net_io.packets_recv + net_io.packets_sent) // 1000,
                'bandwidth_usage': (net_io.bytes_sent + net_io.bytes_recv) // 1024 // 1024,
                'connection_attempts': random.randint(50, 500),
                'firewall_blocks': random.randint(5, 50),
                'latency_ms': random.randint(10, 100)
            }
            
            real_time_data['network_traffic'].append(data_point)
            return data_point
        except Exception as e:
            logger.error(f"Network stats error: {e}")
            # Return mock data if psutil fails
            return {
                'timestamp': datetime.now().isoformat(),
                'packets_sent': random.randint(1000, 5000),
                'packets_recv': random.randint(1000, 5000),
                'bytes_sent': random.randint(1000000, 5000000),
                'bytes_recv': random.randint(1000000, 5000000),
                'packets_per_sec': random.randint(100, 500),
                'bandwidth_usage': random.randint(10, 100),
                'connection_attempts': random.randint(50, 500),
                'firewall_blocks': random.randint(5, 50),
                'latency_ms': random.randint(10, 100)
            }
    
    def generate_advanced_threat_event(self):
        """Generate sophisticated threat detection events"""
        threat_types = [
            'Port Scan', 'DDoS Attack', 'Malware Communication', 
            'Data Exfiltration', 'Brute Force Attempt', 'SQL Injection',
            'Zero-Day Exploit', 'Phishing Attempt', 'Ransomware Activity',
            'Insider Threat', 'IoT Device Compromise', 'API Abuse'
        ]
        
        severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        ai_models = ['Isolation Forest', 'Autoencoder', 'XGBoost', 'LSTM', 'Ensemble', 'Random Forest']
        
        event = {
            'id': f"threat_{int(time.time() * 1000)}",
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': random.choice(threat_types),
            'severity': random.choice(severity_levels),
            'source_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'destination_ip': f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
            'confidence': round(random.uniform(0.7, 0.99), 2),
            'status': 'DETECTED',
            'ai_model': random.choice(ai_models),
            'response_action': random.choice(['BLOCKED', 'QUARANTINED', 'MONITORING', 'INVESTIGATING']),
            'affected_systems': random.randint(1, 15),
            'data_impact_mb': random.randint(1, 5000),
            'mitigation_time_ms': random.randint(50, 500)
        }
        
        # Advanced false positive simulation with improvement over time
        false_positive_chance = 0.1 * (1 - self.false_positive_reduction)
        if random.random() < false_positive_chance:
            event['false_positive'] = True
            system_state['false_positives'] += 1
        else:
            event['false_positive'] = False
        
        real_time_data['threat_events'].append(event)
        self.threat_history.append(event)
        system_state['total_threats'] += 1
        
        if event['severity'] in ['HIGH', 'CRITICAL']:
            system_state['active_incidents'] += 1
            
        return event
    
    def update_comprehensive_system_metrics(self):
        """Update comprehensive system health and performance metrics"""
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'active_connections': random.randint(50, 200),
                'temperature': random.randint(30, 70),
                'network_latency': random.randint(10, 100),
                'response_time': random.randint(5, 50),
                'throughput_mbps': random.randint(100, 1000),
                'encryption_ops': random.randint(1000, 10000),
                'ai_inference_time': round(random.uniform(0.1, 2.0), 2),
                'threat_detection_rate': round(random.uniform(85, 99), 1),
                'system_load': random.randint(1, 100)
            }
            
            real_time_data['system_metrics'].append(metrics)
            
            # Update comprehensive system state
            system_state['system_health'] = max(0, 100 - (metrics['cpu_percent'] + metrics['memory_percent']) / 2)
            system_state['response_time'] = metrics['response_time']
            system_state['network_latency'] = metrics['network_latency']
            
            # Dynamic optimization scoring
            cpu_score = max(0, 100 - metrics['cpu_percent'])
            memory_score = max(0, 100 - metrics['memory_percent'])
            network_score = max(0, 100 - (metrics['network_latency'] / 2))
            response_score = max(0, 100 - metrics['response_time'])
            
            system_state['optimization_score'] = round((cpu_score + memory_score + network_score + response_score) / 4, 1)
            system_state['performance_boost'] = random.randint(40, 60)
            system_state['ai_confidence'] = round(random.uniform(92, 98), 1)
            
            return metrics
        except Exception as e:
            logger.error(f"System metrics error: {e}")
            # Return mock data
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': random.randint(5, 40),
                'memory_percent': random.randint(20, 60),
                'disk_percent': random.randint(10, 50),
                'active_connections': random.randint(50, 200),
                'temperature': random.randint(30, 70),
                'network_latency': random.randint(10, 100),
                'response_time': random.randint(5, 50),
                'throughput_mbps': random.randint(100, 1000),
                'encryption_ops': random.randint(1000, 10000),
                'ai_inference_time': round(random.uniform(0.1, 2.0), 2),
                'threat_detection_rate': round(random.uniform(85, 99), 1),
                'system_load': random.randint(1, 100)
            }
    
    def simulate_ai_training(self):
        """Simulate AI model training processes"""
        # Improve accuracy slightly with each training cycle
        improvement = random.uniform(0.001, 0.005)
        system_state['ai_models']['supervised_accuracy'] = min(0.98, system_state['ai_models']['supervised_accuracy'] + improvement)
        system_state['ai_models']['unsupervised_accuracy'] = min(0.95, system_state['ai_models']['unsupervised_accuracy'] + improvement * 0.8)
        system_state['ai_models']['ensemble_accuracy'] = min(0.99, system_state['ai_models']['ensemble_accuracy'] + improvement * 1.2)
        system_state['ai_models']['accuracy'] = system_state['ai_models']['ensemble_accuracy']
        
        training_data = {
            'timestamp': datetime.now().isoformat(),
            'training_cycle': self.ai_training_cycles,
            'supervised_accuracy': round(system_state['ai_models']['supervised_accuracy'], 3),
            'unsupervised_accuracy': round(system_state['ai_models']['unsupervised_accuracy'], 3),
            'ensemble_accuracy': round(system_state['ai_models']['ensemble_accuracy'], 3),
            'training_loss': round(random.uniform(0.01, 0.1), 4),
            'validation_loss': round(random.uniform(0.02, 0.15), 4),
            'training_samples': random.randint(10000, 100000),
            'training_time_seconds': random.randint(300, 1800),
            'model_type': random.choice(['supervised', 'unsupervised', 'ensemble']),
            'feature_importance': random.randint(50, 200)
        }
        
        real_time_data['ai_training_data'].append(training_data)
        self.ai_training_cycles += 1
        
        return training_data
    
    def optimize_system_performance(self):
        """Simulate system optimization processes"""
        # Improve system metrics
        system_state['optimization_score'] = min(100, system_state['optimization_score'] + random.randint(1, 5))
        system_state['performance_boost'] = min(100, system_state['performance_boost'] + random.randint(1, 3))
        system_state['ai_confidence'] = min(99, system_state['ai_confidence'] + random.uniform(0.1, 0.5))
        
        optimization_data = {
            'timestamp': datetime.now().isoformat(),
            'optimization_cycle': self.optimization_cycles,
            'performance_gain': round(random.uniform(1, 5), 2),
            'memory_optimization': round(random.uniform(5, 15), 2),
            'network_optimization': round(random.uniform(2, 8), 2),
            'security_enhancement': round(random.uniform(1, 3), 2),
            'false_positive_reduction': round(random.uniform(0.5, 2), 2),
            'optimization_type': random.choice(['memory', 'network', 'security', 'performance']),
            'impact_score': random.randint(1, 10)
        }
        
        real_time_data['optimization_logs'].append(optimization_data)
        self.optimization_cycles += 1
        
        # Apply optimizations
        self.false_positive_reduction += optimization_data['false_positive_reduction'] / 100
        
        return optimization_data
    
    def generate_real_news_feed(self):
        """Generate realistic cybersecurity news feed"""
        news_categories = {
            'Vulnerability': [
                "Critical Zero-Day Vulnerability Discovered in Enterprise Software",
                "New Security Patch Released for Major Operating System",
                "Vulnerability Affecting Millions of IoT Devices Discovered"
            ],
            'Threat': [
                "Global Ransomware Attack Targets Healthcare Organizations",
                "Sophisticated APT Group Targeting Financial Institutions",
                "New Malware Variant Bypassing Traditional Security Measures"
            ],
            'Update': [
                "New AI-Powered Threat Detection Algorithm Released",
                "Security Standards Updated for Cloud Infrastructure",
                "Enhanced Encryption Protocols Now Available"
            ]
        }
        
        if random.random() < 0.3:  # 30% chance to add news
            category = random.choice(list(news_categories.keys()))
            news = {
                'id': f"news_{int(time.time() * 1000)}",
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'title': random.choice(news_categories[category]),
                'category': category,
                'priority': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                'source': random.choice(['CISA', 'NIST', 'SANS', 'MITRE', 'OWASP']),
                'impact_level': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                'read_time': f"{random.randint(1, 5)} min read"
            }
            real_time_data['news_feed'].append(news)
            return news
        return None
    
    def generate_threat_intelligence(self):
        """Generate threat intelligence data"""
        intelligence_types = ['IOC', 'TTP', 'Campaign', 'Actor', 'Malware']
        
        intelligence = {
            'timestamp': datetime.now().isoformat(),
            'type': random.choice(intelligence_types),
            'confidence': round(random.uniform(0.7, 0.99), 2),
            'severity': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
            'source': random.choice(['Internal', 'External', 'Partner', 'Open Source']),
            'relevance': round(random.uniform(0.5, 1.0), 2),
            'indicators_count': random.randint(1, 20),
            'last_seen': (datetime.now() - timedelta(hours=random.randint(1, 72))).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        real_time_data['threat_intelligence'].append(intelligence)
        return intelligence

# Initialize enhanced real-time engine
data_engine = AdvancedRealTimeDataEngine()

# Routes
@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@app.route('/auth')
def auth_page():
    """Authentication page"""
    return render_template('auth.html')

@app.route('/dashboard')
@login_required_redirect
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')

@app.route('/network-monitor')
@login_required_redirect
def network_monitor():
    """Network monitoring page"""
    return render_template('network_monitor.html')

@app.route('/ai-analysis')
@login_required_redirect
def ai_analysis():
    """AI analysis page"""
    return render_template('ai_analysis.html')

@app.route('/threat-intelligence')
@login_required_redirect
def threat_intelligence():
    """Threat intelligence page"""
    return render_template('threat_intelligence.html')

@app.route('/system-settings')
@login_required_redirect
def system_settings():
    """System settings page"""
    return render_template('system_settings.html')

@app.route('/optimization-center')
@login_required_redirect
def optimization_center():
    """Optimization center page"""
    return render_template('optimization_center.html')

@app.route('/free-access')
def free_access():
    """Free access redirect - creates a temporary user"""
    try:
        # Create a temporary free user
        conn = get_db_connection()
        if not conn:
            return redirect(url_for('auth_page'))
            
        with conn.cursor() as cur:
            # Generate unique email for free user
            free_email = f"free_user_{int(time.time())}@angelsuccess.com"
            hashed_password = hash_password("free_access_2025")
            
            cur.execute(
                'INSERT INTO users (full_name, email, password, plan) VALUES (%s, %s, %s, %s) RETURNING id',
                ("Free User", free_email, hashed_password, "free")
            )
            user_id = cur.fetchone()['id']
            conn.commit()
        
        conn.close()
        
        token = generate_token(user_id)
        session['token'] = token
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Free access error: {e}")
        return redirect(url_for('auth_page'))

# API Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration"""
    try:
        data = request.get_json()
        full_name = data.get('fullName')
        email = data.get('email')
        password = data.get('password')
        
        if not all([full_name, email, password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        hashed_password = hash_password(password)
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        try:
            with conn.cursor() as cur:
                cur.execute(
                    'INSERT INTO users (full_name, email, password) VALUES (%s, %s, %s) RETURNING id',
                    (full_name, email, hashed_password)
                )
                user_id = cur.fetchone()['id']
                conn.commit()
            
            token = generate_token(user_id)
            session['token'] = token
            return jsonify({
                'success': True, 
                'message': 'Registration successful',
                'token': token
            })
        except psycopg.IntegrityError:
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
            
        with conn.cursor() as cur:
            cur.execute('SELECT id, password, full_name FROM users WHERE email = %s', (email,))
            user = cur.fetchone()
        
        conn.close()
        
        if user:
            user_id, hashed_password, full_name = user['id'], user['password'], user['full_name']
            
            if verify_password(password, hashed_password):
                token = generate_token(user_id)
                session['token'] = token
                return jsonify({
                    'success': True,
                    'message': 'Login successful',
                    'token': token,
                    'user': {'name': full_name, 'email': email}
                })
            else:
                return jsonify({'success': False, 'message': 'Invalid password'}), 401
        else:
            return jsonify({'success': False, 'message': 'User not found'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """User logout"""
    session.pop('token', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/realtime-data')
@login_required
def realtime_data():
    """Enhanced real-time data API endpoint"""
    try:
        # Generate comprehensive real-time data
        network_stats = data_engine.update_network_stats()
        system_metrics = data_engine.update_comprehensive_system_metrics()
        
        # Generate random events
        if random.random() < 0.4:
            data_engine.generate_advanced_threat_event()
        
        if random.random() < 0.1:
            data_engine.generate_real_news_feed()
        
        if random.random() < 0.05:
            data_engine.simulate_ai_training()
        
        if random.random() < 0.08:
            data_engine.generate_threat_intelligence()
        
        # Enhanced chart data
        timeline_labels = [f"{i}:00" for i in range(24)]
        timeline_threats = [random.randint(0, 20) for _ in range(24)]
        timeline_false_positives = [max(0, random.randint(0, threat // 4)) for threat in timeline_threats]
        
        # Enhanced response data
        response_data = {
            'total_threats': system_state['total_threats'],
            'active_incidents': system_state['active_incidents'],
            'ai_confidence': system_state['ai_confidence'],
            'network_traffic': network_stats['bandwidth_usage'],
            'system_health': system_state['system_health'],
            'false_positives': system_state['false_positives'],
            'threat_prevention_rate': system_state['threat_prevention_rate'],
            'optimization_score': system_state['optimization_score'],
            'performance_boost': system_state['performance_boost'],
            'response_time': system_state['response_time'],
            'network_latency': system_state['network_latency'],
            'active_connections': system_metrics['active_connections'],
            'ai_models': system_state['ai_models'],
            'charts': {
                'timeline': {
                    'labels': timeline_labels,
                    'threats': timeline_threats,
                    'false_positives': timeline_false_positives,
                    'performance': [random.randint(70, 95) for _ in range(24)]
                },
                'threat_categories': [
                    random.randint(5, 20),  # Malware
                    random.randint(3, 15),  # Phishing
                    random.randint(2, 12),  # DDoS
                    random.randint(1, 8),   # Insider
                    random.randint(4, 18)   # Exploits
                ],
                'performance': [
                    system_metrics['cpu_percent'],
                    system_metrics['memory_percent'],
                    system_metrics['network_latency'],
                    system_metrics['response_time'],
                    random.randint(85, 99),   # AI Performance
                    random.randint(90, 98)    # Security
                ],
                'ai_models_comparison': [
                    round(system_state['ai_models']['supervised_accuracy'] * 100, 1),
                    round(system_state['ai_models']['unsupervised_accuracy'] * 100, 1),
                    round(system_state['ai_models']['ensemble_accuracy'] * 100, 1)
                ]
            },
            'threat_feed': list(real_time_data['threat_events'])[-10:],
            'network_metrics': list(real_time_data['network_traffic'])[-15:],
            'ai_training_data': list(real_time_data['ai_training_data'])[-5:],
            'optimization_logs': list(real_time_data['optimization_logs'])[-5:],
            'threat_intelligence': list(real_time_data['threat_intelligence'])[-10:]
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Real-time data error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear-threats', methods=['POST'])
@login_required
def clear_threats():
    """Clear threat history"""
    real_time_data['threat_events'].clear()
    system_state['total_threats'] = 0
    system_state['active_incidents'] = 0
    system_state['false_positives'] = 0
    return jsonify({'success': True, 'message': 'Threat history cleared'})

@app.route('/api/start-ai-training', methods=['POST'])
@login_required
def start_ai_training():
    """Start AI model training"""
    try:
        training_data = data_engine.simulate_ai_training()
        return jsonify({
            'success': True,
            'message': 'AI training started successfully',
            'training_data': training_data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/optimize-system', methods=['POST'])
@login_required
def optimize_system():
    """Run system optimization"""
    try:
        optimization_data = data_engine.optimize_system_performance()
        return jsonify({
            'success': True,
            'message': 'System optimization completed',
            'optimization_data': optimization_data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system-status')
@login_required
def system_status():
    """Enhanced system status API"""
    return jsonify({
        'status': 'operational',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'ai_models': 'online',
            'network_monitor': 'active',
            'threat_detection': 'enabled',
            'data_processing': 'running',
            'optimization_engine': 'active'
        },
        'performance': {
            'response_time': f"{system_state['response_time']}ms",
            'accuracy': f"{system_state['ai_confidence']}%",
            'optimization_score': f"{system_state['optimization_score']}%",
            'performance_boost': f"{system_state['performance_boost']}%",
            'threat_prevention': f"{system_state['threat_prevention_rate']}%"
        }
    })

# Debug routes
@app.route('/create-test-user')
def create_test_user():
    """Create a test user for debugging"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database connection failed'})
            
        with conn.cursor() as cur:
            # Check if test user already exists
            cur.execute('SELECT id FROM users WHERE email = %s', ('test@example.com',))
            existing_user = cur.fetchone()
            
            if existing_user:
                return jsonify({'success': True, 'message': 'Test user already exists'})
            
            # Create test user
            hashed_password = hash_password('password123')
            cur.execute(
                'INSERT INTO users (full_name, email, password) VALUES (%s, %s, %s) RETURNING id',
                ('Test User', 'test@example.com', hashed_password)
            )
            conn.commit()
        
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': 'Test user created successfully',
            'credentials': {
                'email': 'test@example.com',
                'password': 'password123'
            }
        })
        
    except Exception as e:
        logger.error(f"Test user creation error: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/debug-users')
def debug_users():
    """Debug route to see all users in database"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'})
            
        with conn.cursor() as cur:
            cur.execute('SELECT id, full_name, email, plan FROM users')
            users = cur.fetchall()
        
        conn.close()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user['id'],
                'full_name': user['full_name'],
                'email': user['email'],
                'plan': user['plan']
            })
        
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def start_enhanced_real_time_updates():
    """Start comprehensive background real-time data updates"""
    def update_loop():
        while True:
            try:
                # Update all data points periodically
                if random.random() < 0.3:
                    data_engine.generate_advanced_threat_event()
                
                if random.random() < 0.2:
                    data_engine.generate_real_news_feed()
                
                if random.random() < 0.1:
                    data_engine.generate_threat_intelligence()
                
                time.sleep(2)
            except Exception as e:
                logger.error(f"Update loop error: {e}")
                time.sleep(5)
    
    update_thread = threading.Thread(target=update_loop, daemon=True)
    update_thread.start()

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'success': False, 'error': 'Authentication required'}), 401

if __name__ == '__main__':
    # Initialize database and create default user
    init_db()
    
    # Start enhanced real-time updates
    start_enhanced_real_time_updates()
    
    port = int(os.environ.get('PORT', 5000))
    
    print("🚀 Starting Enhanced ANGELSUCCESS Cybersecurity Platform...")
    print(f"📄 Landing Page: http://localhost:{port}")
    print(f"🔐 Auth Page: http://localhost:{port}/auth")
    print(f"📊 Dashboard: http://localhost:{port}/dashboard")
    print(f"🌐 Network Monitor: http://localhost:{port}/network-monitor")
    print(f"🤖 AI Analysis: http://localhost:{port}/ai-analysis")
    print(f"🔍 Threat Intelligence: http://localhost:{port}/threat-intelligence")
    print(f"⚙️ System Settings: http://localhost:{port}/system-settings")
    print(f"🚀 Optimization Center: http://localhost:{port}/optimization-center")
    print(f"🆓 Free Access: http://localhost:{port}/free-access")
    print("🐛 Debug Routes:")
    print(f"   • http://localhost:{port}/create-test-user")
    print(f"   • http://localhost:{port}/debug-users")
    print("🔑 Test Credentials:")
    print("   • Email: test@example.com")
    print("   • Password: password123")
    print("=" * 60)
    
    # Run the Flask application
    app.run(debug=True, host='0.0.0.0', port=port)