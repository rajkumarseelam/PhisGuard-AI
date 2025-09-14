#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import sys
from queue import Queue
from uuid import uuid4
import time
import threading
import psycopg2
from psycopg2 import pool
import json
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add parent directory to path to import dnstwist
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dnstwist


PORT = int(os.environ.get('PORT', 8000))
HOST= os.environ.get('HOST', '127.0.0.1')
THREADS = int(os.environ.get('THREADS', dnstwist.THREAD_COUNT_DEFAULT))
NAMESERVERS = os.environ.get('NAMESERVERS') or os.environ.get('NAMESERVER')
SESSION_TTL = int(os.environ.get('SESSION_TTL', 3600))
SESSION_MAX = int(os.environ.get('SESSION_MAX', 10)) # max concurrent sessions
DOMAIN_MAXLEN = int(os.environ.get('DOMAIN_MAXLEN', 15))
WEBAPP_HTML = os.environ.get('WEBAPP_HTML', 'webapp.html')
WEBAPP_DIR = os.environ.get('WEBAPP_DIR', os.path.dirname(os.path.abspath(__file__)))

# PostgreSQL Configuration
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_NAME = os.environ.get('DB_NAME', 'phisguard')
DB_USER = os.environ.get('DB_USER', 'postgres')
DB_PASS = os.environ.get('DB_PASS', 'postgres')
DB_MIN_CONN = int(os.environ.get('DB_MIN_CONN', 1))
DB_MAX_CONN = int(os.environ.get('DB_MAX_CONN', 10))
DB_ENABLE = os.environ.get('DB_ENABLE', 'true').lower() == 'true'

DOMAIN_BLOCKLIST = []

DICTIONARY = ('auth', 'account', 'confirm', 'connect', 'enroll', 'http', 'https', 'info', 'login', 'mail', 'my',
	'online', 'payment', 'portal', 'recovery', 'register', 'ssl', 'safe', 'secure', 'signin', 'signup', 'support',
	'update', 'user', 'verify', 'verification', 'web', 'www')
TLD_DICTIONARY = ('com', 'net', 'org', 'info', 'cn', 'co', 'eu', 'de', 'uk', 'pw', 'ga', 'gq', 'tk', 'ml', 'cf',
	'app', 'biz', 'top', 'xyz', 'online', 'site', 'live')


sessions = []
app = Flask(__name__)

# Database connection pool
db_pool = None

def init_db():
    """Initialize database connection and create tables if they don't exist"""
    global db_pool
    
    if not DB_ENABLE:
        print("Database integration is disabled.")
        return
    
    try:
        # Create a connection pool
        db_pool = psycopg2.pool.SimpleConnectionPool(
            DB_MIN_CONN, DB_MAX_CONN,
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        
        # Get a connection to create tables
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        # Create scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id VARCHAR(36) PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                domain VARCHAR(255) NOT NULL,
                total_domains INTEGER NOT NULL,
                registered_domains INTEGER
            );
        """)
        
        # Create domains table for storing scan results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                id SERIAL PRIMARY KEY,
                scan_id VARCHAR(36) REFERENCES scans(id),
                domain VARCHAR(255) NOT NULL,
                fuzzer VARCHAR(50),
                dns_a VARCHAR(255),
                dns_aaaa VARCHAR(255),
                dns_mx VARCHAR(255),
                dns_ns VARCHAR(255),
                geoip VARCHAR(255),
                created_at TIMESTAMP NOT NULL
            );
        """)
        
        conn.commit()
        db_pool.putconn(conn)
        print("Database initialized successfully.")
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        db_pool = None

def save_scan_to_db(session):
    """Save scan results to database"""
    if not DB_ENABLE or db_pool is None:
        return
    
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        # Save scan information
        timestamp = datetime.fromtimestamp(session.timestamp)
        cursor.execute(
            "INSERT INTO scans (id, timestamp, domain, total_domains, registered_domains) VALUES (%s, %s, %s, %s, %s)",
            (session.id, timestamp, session.url.domain, len(session.permutations()), len(session.permutations(registered=True)))
        )
        
        # Save domain information
        domains = session.permutations(registered=True)
        for domain in domains:
            dns_a = json.dumps(domain.get('dns_a', [])) if domain.get('dns_a') else None
            dns_aaaa = json.dumps(domain.get('dns_aaaa', [])) if domain.get('dns_aaaa') else None
            dns_mx = json.dumps(domain.get('dns_mx', [])) if domain.get('dns_mx') else None
            dns_ns = json.dumps(domain.get('dns_ns', [])) if domain.get('dns_ns') else None
            geoip = json.dumps(domain.get('geoip')) if domain.get('geoip') else None
            
            cursor.execute(
                """INSERT INTO domains 
                   (scan_id, domain, fuzzer, dns_a, dns_aaaa, dns_mx, dns_ns, geoip, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (session.id, domain.get('domain'), domain.get('fuzzer'), 
                 dns_a, dns_aaaa, dns_mx, dns_ns, geoip, timestamp)
            )
        
        conn.commit()
        db_pool.putconn(conn)
        return True
    except Exception as e:
        print(f"Database error: {e}")
        if conn:
            db_pool.putconn(conn)
        return False

def get_historical_scans(limit=10):
    """Get historical scans from database"""
    if not DB_ENABLE or db_pool is None:
        return []
    
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        cursor.execute(
            """SELECT id, timestamp, domain, total_domains, registered_domains 
               FROM scans ORDER BY timestamp DESC LIMIT %s""",
            (limit,)
        )
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'timestamp': row[1].timestamp(),
                'domain': row[2],
                'total': row[3],
                'registered': row[4]
            })
        
        db_pool.putconn(conn)
        return scans
    except Exception as e:
        print(f"Database error: {e}")
        if 'conn' in locals():
            db_pool.putconn(conn)
        return []

def get_scan_details(scan_id):
    """Get detailed scan results from database"""
    if not DB_ENABLE or db_pool is None:
        return None
    
    try:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        
        # Get scan info
        cursor.execute("SELECT id, timestamp, domain, total_domains, registered_domains FROM scans WHERE id = %s", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            db_pool.putconn(conn)
            return None
        
        scan = {
            'id': scan_row[0],
            'timestamp': scan_row[1].timestamp(),
            'domain': scan_row[2],
            'total': scan_row[3],
            'registered': scan_row[4],
            'domains': []
        }
        
        # Get domain details
        cursor.execute(
            "SELECT domain, fuzzer, dns_a, dns_aaaa, dns_mx, dns_ns, geoip FROM domains WHERE scan_id = %s",
            (scan_id,)
        )
        
        for row in cursor.fetchall():
            domain = {
                'domain': row[0],
                'fuzzer': row[1]
            }
            
            if row[2]:  # dns_a
                domain['dns_a'] = json.loads(row[2])
            if row[3]:  # dns_aaaa
                domain['dns_aaaa'] = json.loads(row[3])
            if row[4]:  # dns_mx
                domain['dns_mx'] = json.loads(row[4])
            if row[5]:  # dns_ns
                domain['dns_ns'] = json.loads(row[5])
            if row[6]:  # geoip
                domain['geoip'] = json.loads(row[6])
            
            scan['domains'].append(domain)
        
        db_pool.putconn(conn)
        return scan
    except Exception as e:
        print(f"Database error: {e}")
        if 'conn' in locals():
            db_pool.putconn(conn)
        return None

def janitor(sessions):
    while True:
        time.sleep(1)
        for s in sorted(sessions, key=lambda x: x.timestamp):
            if s.jobs.empty() and s.threads:
                # Save completed scan to database before stopping
                if DB_ENABLE and db_pool and not s.jobs.qsize() and s.threads:
                    save_scan_to_db(s)
                s.stop()
                continue
            if (s.timestamp + SESSION_TTL) < time.time():
                sessions.remove(s)
                continue

class Session():
	def __init__(self, url, nameservers=None, thread_count=THREADS):
		self.id = str(uuid4())
		self.timestamp = int(time.time())
		self.url = dnstwist.UrlParser(url)
		self.nameservers = nameservers
		self.thread_count = thread_count
		self.jobs = Queue()
		self.threads = []
		self.fuzzer = dnstwist.Fuzzer(self.url.domain, dictionary=DICTIONARY, tld_dictionary=TLD_DICTIONARY)
		self.fuzzer.generate()
		self.permutations = self.fuzzer.permutations

	def scan(self):
		for domain in self.fuzzer.domains:
			self.jobs.put(domain)
		for _ in range(self.thread_count):
			worker = dnstwist.Scanner(self.jobs)
			worker.option_extdns = dnstwist.MODULE_DNSPYTHON
			worker.option_geoip = dnstwist.MODULE_GEOIP
			if self.nameservers:
				worker.nameservers = self.nameservers.split(',')
			worker.start()
			self.threads.append(worker)

	def stop(self):
		self.jobs.queue.clear()
		for worker in self.threads:
			worker.stop()
		for worker in self.threads:
			worker.join()
		self.threads.clear()

	def domains(self):
		return self.permutations(registered=True, unicode=True)

	def status(self):
		total = len(self.permutations())
		remaining = max(self.jobs.qsize(), len(self.threads))
		complete = total - remaining
		registered = len(self.permutations(registered=True))
		return {
			'id': self.id,
			'timestamp': self.timestamp,
			'url': self.url.full_uri(),
			'domain': self.url.domain,
			'total': total,
			'complete': complete,
			'remaining': remaining,
			'registered': registered
			}

	def csv(self):
		return dnstwist.Format(self.permutations(registered=True)).csv()

	def json(self):
		return dnstwist.Format(self.permutations(registered=True)).json()

	def list(self):
		return dnstwist.Format(self.permutations()).list()


@app.route('/')
def root():
	return send_from_directory(WEBAPP_DIR, WEBAPP_HTML)


@app.route('/api/scans', methods=['POST'])
def api_scan():
	if sum([1 for s in sessions if not s.jobs.empty()]) >= SESSION_MAX:
		return jsonify({'message': 'Too many scan sessions - please retry in a minute'}), 500
	j = request.get_json(force=True)
	if 'url' not in j:
		return jsonify({'message': 'Bad request'}), 400
	try:
		_, domain, _ = dnstwist.domain_tld(j.get('url'))
	except Exception:
		return jsonify({'message': 'Bad request'}), 400
	if len(domain) > DOMAIN_MAXLEN:
		return jsonify({'message': 'Domain name is too long'}), 400
	for block in DOMAIN_BLOCKLIST:
		if str(block) in domain:
			return jsonify({'message': 'Not allowed'}), 400
	try:
		session = Session(j.get('url'), nameservers=NAMESERVERS)
	except Exception as err:
		return jsonify({'message': 'Invalid domain name'}), 400
	else:
		session.scan()
		sessions.append(session)
	return jsonify(session.status()), 201


@app.route('/api/scans/<sid>')
def api_status(sid):
	for s in sessions:
		if s.id == sid:
			return jsonify(s.status())
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/domains')
def api_domains(sid):
	for s in sessions:
		if s.id == sid:
			return jsonify(s.domains())
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/csv')
def api_csv(sid):
	for s in sessions:
		if s.id == sid:
			return s.csv(), 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=dnstwist.csv'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/json')
def api_json(sid):
	for s in sessions:
		if s.id == sid:
			return s.json(), 200, {'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename=dnstwist.json'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/list')
def api_list(sid):
	for s in sessions:
		if s.id == sid:
			return s.list(), 200, {'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename=dnstwist.txt'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/stop', methods=['POST'])
def api_stop(sid):
	for s in sessions:
		if s.id == sid:
			s.stop()
			return jsonify({})
	return jsonify({'message': 'Scan session not found'}), 404


# New API endpoints for historical data
@app.route('/api/history', methods=['GET'])
def api_history():
    limit = request.args.get('limit', default=10, type=int)
    scans = get_historical_scans(limit)
    return jsonify(scans)


@app.route('/api/history/<scan_id>', methods=['GET'])
def api_history_detail(scan_id):
    scan = get_scan_details(scan_id)
    if scan:
        return jsonify(scan)
    return jsonify({'message': 'Scan not found'}), 404


# Initialize database
init_db()

cleaner = threading.Thread(target=janitor, args=(sessions,))
cleaner.daemon = True
cleaner.start()

if __name__ == '__main__':
	app.run(host=HOST, port=PORT)
