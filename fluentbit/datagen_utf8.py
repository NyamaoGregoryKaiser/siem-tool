from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import random
from bson import ObjectId
from faker import Faker
import uuid
import time
import hashlib
import json
import re
from collections import defaultdict
import numpy as np
from scipy.special import softmax
import pickle
import os
import argparse

# Initialize Faker for realistic data generation
fake = Faker()

# MongoDB connection setup
client = None
db = None
collection = None

try:
    client = MongoClient("mongodb://localhost:27017")
    # Test the connection
    client.server_info()
    db = client["log_anomaly"]
    collection = db["logs"]
    print("Successfully connected to MongoDB")
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")
    raise

# Target devices as specified
devices = ["LAPTOP-45TZ9WK", "Wazuh", "WORKSTATION-B7Q4PL"]

# Define date range from March 1 to May 30, 2025
start_date = datetime(2025, 3, 1, tzinfo=timezone.utc)
end_date = datetime(2025, 5, 30, tzinfo=timezone.utc)
date_range = (end_date - start_date).days

# Add IP range definitions
IP_RANGES = {
    'kenya': {
        'safaricom': {
            'base': '197.232',
            'range': 235,  # 197.232.0.0 - 197.235.255.255
            'weight': 0.5  # 50% of Kenyan IPs
        },
        'telkom': {
            'base': '196.202',
            'range': 202,  # 196.202.0.0 - 196.202.255.255
            'weight': 0.3  # 30% of Kenyan IPs
        },
        'jamii': {
            'base': '41.89',
            'range': 89,   # 41.89.0.0 - 41.89.255.255
            'weight': 0.2  # 20% of Kenyan IPs
        }
    },
    'foreign': {
        'nigeria': {
            'mtn': {'base': '102.89', 'range': 89},
            'globacom': {'base': '197.211', 'range': 211},
            'airtel': {'base': '154.113', 'range': 113}
        },
        'south_africa': {
            'vodacom': {'base': '41.0', 'range': 127},
            'mtn': {'base': '197.80', 'range': 87},
            'afrihost': {'base': '169.239', 'range': 239}
        },
        'india': {
            'jio': {'base': '49.32', 'range': 63},
            'airtel': {'base': '125.16', 'range': 23},
            'bsnl': {'base': '117.192', 'range': 207}
        }
    }
}

def generate_random_ip(base, subnet_range):
    """Generate a random IP address within a given subnet range"""
    base_parts = base.split('.')
    ip_parts = [
        base_parts[0],
        str(random.randint(int(base_parts[1]), subnet_range)),
        str(random.randint(0, 255)),
        str(random.randint(0, 255))
    ]
    return '.'.join(ip_parts)

def get_ip_for_event(severity_level, is_anomalous=False):
    """
    Generate an IP address based on event severity and anomaly status.
    Higher severity events are more likely to come from foreign IPs.
    """
    # 95% of events should be from Kenya
    if random.random() < 0.95:
        # Select Kenyan provider based on weights
        provider = random.choices(
            list(IP_RANGES['kenya'].keys()),
            weights=[p['weight'] for p in IP_RANGES['kenya'].values()]
        )[0]
        ip_range = IP_RANGES['kenya'][provider]
        return generate_random_ip(ip_range['base'], ip_range['range'])
    else:
        # 5% of events come from foreign IPs
        # Higher severity events are more likely to be foreign
        if severity_level <= 2 or is_anomalous:  # Critical or High severity
            # 80% chance of foreign IP for critical/high events
            if random.random() < 0.8:
                country = random.choice(list(IP_RANGES['foreign'].keys()))
                provider = random.choice(list(IP_RANGES['foreign'][country].keys()))
                ip_range = IP_RANGES['foreign'][country][provider]
                return generate_random_ip(ip_range['base'], ip_range['range'])
        
        # Fallback to Kenyan IP
        provider = random.choices(
            list(IP_RANGES['kenya'].keys()),
            weights=[p['weight'] for p in IP_RANGES['kenya'].values()]
        )[0]
        ip_range = IP_RANGES['kenya'][provider]
        return generate_random_ip(ip_range['base'], ip_range['range'])

class AILogSequenceModel:
    """
    An AI model for generating realistic log sequences using transition probabilities
    and contextual awareness to create meaningful security event patterns.
    """
    def __init__(self):
        # Initialize transition probability matrices
        self.event_transition_matrix = {}
        self.device_event_preferences = {}
        self.account_behavior_profiles = {}
        self.anomaly_patterns = {}
        
        # Initialize the model
        self.initialize_model()
        
    def initialize_model(self):
        """Initialize the AI model with realistic transition probabilities and patterns"""
        # Define core event types
        event_types = [
            'logon_attempt', 'logon_success', 'logon_failure', 'explicit_logon',
            'credential_read', 'special_privileges', 'service_install', 'service_start',
            'service_stop', 'multiple_failures', 'account_lockout', 'account_unlock',
            'password_reset', 'logoff'
        ]
        
        # Define the base transition matrix (what events typically follow others)
        # This creates a realistic workflow of events
        self.event_transition_matrix = {
            'logon_attempt': {
                'logon_success': 0.85, 
                'logon_failure': 0.15
            },
            'logon_failure': {
                'logon_attempt': 0.75, 
                'multiple_failures': 0.25
            },
            'multiple_failures': {
                'account_lockout': 0.80, 
                'logon_attempt': 0.20
            },
            'logon_success': {
                'special_privileges': 0.15, 
                'credential_read': 0.25, 
                'service_install': 0.05, 
                'explicit_logon': 0.15, 
                'logoff': 0.40
            },
            'special_privileges': {
                'service_install': 0.30, 
                'credential_read': 0.30, 
                'logoff': 0.40
            },
            'service_install': {
                'service_start': 0.80, 
                'logoff': 0.20
            },
            'service_start': {
                'service_stop': 0.40, 
                'logoff': 0.60
            },
            'service_stop': {
                'service_start': 0.30, 
                'logoff': 0.70
            },
            'credential_read': {
                'explicit_logon': 0.30, 
                'credential_read': 0.20, 
                'logoff': 0.50
            },
            'explicit_logon': {
                'credential_read': 0.30, 
                'special_privileges': 0.20, 
                'logoff': 0.50
            },
            'account_lockout': {
                'account_unlock': 0.70, 
                'password_reset': 0.30
            },
            'account_unlock': {
                'logon_attempt': 1.0
            },
            'password_reset': {
                'logon_attempt': 1.0
            },
            'logoff': {
                'logon_attempt': 1.0
            }
        }
        
        # Device-specific event patterns
        self.device_event_preferences = {
            "LAPTOP-45TZ9WK": {
                # Laptops tend to have more logons/logoffs and fewer service operations
                'logon_attempt': 1.5,
                'logoff': 1.3,
                'credential_read': 1.2,
                'service_install': 0.5,
                'service_start': 0.6,
                'service_stop': 0.6
            },
            "SERVER-CORE01": {
                # Servers have more service operations and special privileges
                'service_install': 1.5,
                'service_start': 1.4,
                'service_stop': 1.4,
                'special_privileges': 1.3,
                'credential_read': 1.2,
                'logon_attempt': 0.8,
                'logoff': 0.7
            },
            "WORKSTATION-B7Q4PL": {
                # Workstations are somewhere in between
                'logon_attempt': 1.2,
                'credential_read': 1.1,
                'explicit_logon': 1.2,
                'service_install': 0.8
            }
        }
        
        # Account behavior profiles (admins vs. regular users)
        self.account_behavior_profiles = {
            "admin": {
                'special_privileges': 1.8,
                'service_install': 1.5,
                'service_start': 1.4,
                'service_stop': 1.4,
                'credential_read': 1.3,
                'explicit_logon': 1.3
            },
            "service": {
                'service_start': 2.0,
                'service_stop': 2.0,
                'logon_success': 1.5,
                'logoff': 1.5,
                'special_privileges': 0.5
            },
            "user": {
                'logon_attempt': 1.3,
                'logoff': 1.3,
                'credential_read': 0.9,
                'special_privileges': 0.3,
                'service_install': 0.2
            }
        }
        
        # Anomaly patterns - how events change during anomalous behavior
        self.anomaly_patterns = {
            # Credential theft pattern
            'credential_theft': {
                'credential_read': 3.0,
                'explicit_logon': 2.0,
                'special_privileges': 1.5
            },
            # Service installation pattern (potential malware)
            'malware_install': {
                'service_install': 3.0,
                'service_start': 2.0,
                'special_privileges': 2.0
            },
            # Account takeover pattern
            'account_takeover': {
                'logon_failure': 2.0,
                'multiple_failures': 2.0,
                'logon_success': 1.0,
                'special_privileges': 2.5,
                'credential_read': 2.0
            },
            # Lateral movement pattern
            'lateral_movement': {
                'explicit_logon': 3.0,
                'credential_read': 2.0,
                'special_privileges': 1.5
            }
        }
        
        # Cache the results to avoid recalculation
        self._cached_next_events = {}
    
    def get_next_event(self, current_event, device, account_type, is_anomalous=False):
        """
        Determine the next logical event based on the current event, device, and account type
        using the AI transition model with weighted probabilities.
        """
        # Create a cache key
        cache_key = f"{current_event}:{device}:{account_type}:{is_anomalous}"
        
        # Return cached result if available
        if cache_key in self._cached_next_events:
            return self._cached_next_events[cache_key]
        
        # If we don't have a current event, start with logon_attempt
        if not current_event or current_event not in self.event_transition_matrix:
            return 'logon_attempt'
        
        # Get basic transitions for this event
        transitions = self.event_transition_matrix[current_event].copy()
        
        # Apply device-specific preferences
        device_prefs = self.device_event_preferences.get(device, {})
        for event, prob in transitions.items():
            transitions[event] *= device_prefs.get(event, 1.0)
        
        # Apply account behavior profile
        account_prefs = self.account_behavior_profiles.get(account_type, {})
        for event, prob in transitions.items():
            transitions[event] *= account_prefs.get(event, 1.0)
        
        # Apply anomaly patterns if applicable
        if is_anomalous:
            # Choose a random anomaly pattern
            anomaly_type = random.choice(list(self.anomaly_patterns.keys()))
            anomaly_prefs = self.anomaly_patterns[anomaly_type]
            
            for event, prob in transitions.items():
                transitions[event] *= anomaly_prefs.get(event, 1.0)
        
        # Convert to list of events and probabilities for random selection
        events = list(transitions.keys())
        weights = list(transitions.values())
        
        # Normalize weights to sum to 1
        total_weight = sum(weights)
        if total_weight == 0:  # Fallback if all weights are zero
            return random.choice(list(self.event_transition_matrix.keys()))
        
        norm_weights = [w/total_weight for w in weights]
        
        # Select next event based on weighted probabilities
        next_event = np.random.choice(events, p=norm_weights)
        
        # Cache the result
        self._cached_next_events[cache_key] = next_event
        
        return next_event

class LogSequenceGenerator:
    """
    A tool that creates realistic log sequences using state models.
    Uses an AI-driven approach to generate sequences of events that make logical sense.
    """
    def __init__(self):
        # Map user accounts to their behavior patterns
        self.account_states = {}
        
        # Event ID mappings
        self.event_id_mapping = {
            'logon_attempt': [4648],
            'logon_success': [4624],
            'logon_failure': [4625],
            'explicit_logon': [4648],
            'credential_read': [5379],
            'special_privileges': [4672],
            'service_install': [7045],
            'service_start': [7036],
            'service_stop': [7036],
            'multiple_failures': [4625],
            'account_lockout': [4740],
            'account_unlock': [4767],
            'password_reset': [4724],
            'logoff': [4634]
        }
        
        # Keep track of services installed
        self.services = {}
        
        # Generate initial account states
        self.account_names = {}
        self.session_ids = {}
        
        # Initialize the AI model for event sequencing
        self.ai_model = AILogSequenceModel()
        
        # Track active sessions and their event chains
        self.active_sessions = {}
        
        # Track persistent behavioral patterns across sessions
        self.account_behavior_history = defaultdict(list)
        
    def get_account_for_device(self, device, anomalous=False):
        """Get or create an account for a device"""
        device_hash = hashlib.md5(device.encode()).hexdigest()[:8]
        
        if device not in self.account_names:
            # Create accounts per device - admins, service accounts, and regular users
            accounts = []
            
            # Admin account
            admin_account = {
                "name": f"admin-{device_hash}",
                "sid": f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-1000",
                "is_admin": True,
                "account_type": "admin",
                "state": "logged_off",
                "failed_attempts": 0,
                "locked": False
            }
            accounts.append(admin_account)
            
            # Service accounts (1-2)
            for i in range(random.randint(1, 2)):
                service_account = {
                    "name": f"svc-{device_hash}-{i+1}",
                    "sid": f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{1001+i}",
                    "is_admin": False,
                    "account_type": "service",
                    "state": "logged_off",
                    "failed_attempts": 0,
                    "locked": False
                }
                accounts.append(service_account)
            
            # Regular user accounts (2-3)
            for i in range(random.randint(2, 3)):
                user_account = {
                    "name": f"user{i+1}-{device_hash}",
                    "sid": f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{1010+i}",
                    "is_admin": False,
                    "account_type": "user",
                    "state": "logged_off",
                    "failed_attempts": 0,
                    "locked": False
                }
                accounts.append(user_account)
                
            self.account_names[device] = accounts
        
        # Get account selection based on anomalous flag
        accounts = self.account_names[device]
        
        if anomalous:
            # For anomalous activities, prefer admin accounts (70% chance)
            admin_accounts = [acc for acc in accounts if acc["is_admin"]]
            if admin_accounts and random.random() < 0.7:
                account = random.choice(admin_accounts)
            else:
                # Sometimes choose non-admin accounts for anomalies to avoid patterns
                non_admin_accounts = [acc for acc in accounts if not acc["is_admin"]]
                if non_admin_accounts:
                    account = random.choice(non_admin_accounts)
                else:
                    account = random.choice(accounts)
        else:
            # For regular activities, use weighted selection based on account type
            # Admins are less active in normal operation
            weights = [0.2 if acc["is_admin"] else 
                      (0.3 if acc["account_type"] == "service" else 0.5)
                      for acc in accounts]
            
            # Normalize weights
            total_weight = sum(weights)
            norm_weights = [w/total_weight for w in weights]
            
            # Select account based on weights
            account_index = np.random.choice(range(len(accounts)), p=norm_weights)
            account = accounts[account_index]
            
        return account
    
    def get_session_id(self, device, account_name):
        """Get or generate a session ID for an account"""
        key = f"{device}:{account_name}"
        
        # If the account is logged off, generate a new session ID
        account = next((acc for acc in self.account_names.get(device, []) 
                       if acc["name"] == account_name), None)
        
        if account and account["state"] == "logged_off":
            self.session_ids[key] = f"0x{random.randint(0x10000, 0xFFFFF):x}"
            
            # Initialize a new event chain for this session
            session_chain_key = f"{device}:{account_name}:{self.session_ids[key]}"
            self.active_sessions[session_chain_key] = {
                "current_event": None,
                "events": [],
                "anomalous": False
            }
            
        elif key not in self.session_ids:
            # Fallback - should not normally happen
            self.session_ids[key] = f"0x{random.randint(0x10000, 0xFFFFF):x}"
            
            # Initialize a new event chain
            session_chain_key = f"{device}:{account_name}:{self.session_ids[key]}"
            self.active_sessions[session_chain_key] = {
                "current_event": None,
                "events": [],
                "anomalous": False
            }
            
        return self.session_ids[key]
    
    def get_session_chain(self, device, account_name, session_id):
        """Get the event chain for a specific session"""
        session_chain_key = f"{device}:{account_name}:{session_id}"
        
        if session_chain_key not in self.active_sessions:
            # Initialize if not exists
            self.active_sessions[session_chain_key] = {
                "current_event": None,
                "events": [],
                "anomalous": False
            }
            
        return self.active_sessions[session_chain_key]
    
    def get_next_event_type(self, device, account, session_id, anomalous=False):
        """Determine the next logical event type based on account state and session history"""
        account_type = account.get("account_type", "user")
        account_name = account.get("name", "unknown")
        
        # Get the current session chain
        session_chain = self.get_session_chain(device, account_name, session_id)
        
        # Mark the session as anomalous if requested
        if anomalous:
            session_chain["anomalous"] = True
        
        # Get current state
        current_state = account.get("state", "logged_off")
        current_event = session_chain.get("current_event")
        
        # If logged off, only logical next event is a logon attempt
        if current_state == "logged_off":
            next_event = "logon_attempt"
        else:
            # Use the AI model to determine the next logical event
            next_event = self.ai_model.get_next_event(
                current_event, 
                device, 
                account_type, 
                is_anomalous=session_chain["anomalous"]
            )
        
        # Update the session chain
        session_chain["current_event"] = next_event
        session_chain["events"].append(next_event)
        
        return next_event
    
    def update_account_state(self, account, event_type, success=True):
        """Update the account state based on the event"""
        # Handle login-related state changes
        if event_type == "logon_attempt":
            if success:
                account["state"] = "logon_success"
                account["failed_attempts"] = 0
            else:
                account["state"] = "logon_failure"
                account["failed_attempts"] = account.get("failed_attempts", 0) + 1
                
                # Lock account after too many failures
                if account["failed_attempts"] >= 5:
                    account["locked"] = True
                    account["state"] = "account_lockout"
        
        # Handle account management states
        elif event_type == "account_unlock":
            account["locked"] = False
            account["failed_attempts"] = 0
            account["state"] = "account_unlock"
        
        elif event_type == "password_reset":
            account["failed_attempts"] = 0
            account["state"] = "password_reset"
        
        # Handle session termination
        elif event_type == "logoff":
            account["state"] = "logged_off"
        
        # For other events, just update the state
        else:
            account["state"] = event_type
            
        return account
    
    def generate_event_id(self, event_type):
        """Get an event ID corresponding to the event type"""
        if event_type in self.event_id_mapping:
            return random.choice(self.event_id_mapping[event_type])
        # Default fallback IDs
        return random.choice([5379, 4625, 4648, 4672, 7045])
    
    def get_service_name(self, device, create_new=False):
        """Get or create a service name for a device"""
        if device not in self.services or create_new:
            # Common business software vendors
            vendor_names = ["Contoso", "Fabrikam", "Northwind", "Adventure", 
                          "Tailspin", "Alpine", "Coho", "Litware", "Adatum"]
            
            # Common service types
            service_types = [
                "Backup", "Update", "Sync", "Monitor", "Security", 
                "Remote", "Management", "Analytics", "Scheduler", "Database"
            ]
            
            # Generate service name with a realistic pattern
            service_name = f"{random.choice(vendor_names)}{random.choice(service_types)}Service"
            
            # Generate a realistic installation path
            install_paths = [
                f"C:\\Program Files\\{random.choice(vendor_names)}\\{service_name}\\{service_name}.exe",
                f"C:\\Program Files (x86)\\{random.choice(vendor_names)}\\{service_name}\\{service_name}.exe",
                f"C:\\{random.choice(vendor_names)}\\{service_name}\\bin\\{service_name}.exe"
            ]
            service_path = random.choice(install_paths)
            
            if device not in self.services:
                self.services[device] = []
                
            # Create new service entry
            self.services[device].append({
                "name": service_name,
                "path": service_path,
                "state": "installed",
                "legitimate": not create_new or random.random() > 0.7  # 70% of newly created services are legitimate
            })
        
        if not create_new and device in self.services and self.services[device]:
            # Return an existing service
            return random.choice(self.services[device])
        
        # Return the newly created service
        return self.services[device][-1]

def generate_realistic_message(event_type, event_id, account, device, session_id, log_date, sequence_gen, anomalous=False):
    """Generate a realistic log message based on the event type and context"""
    templates = {
        'logon_attempt': "An account logon was attempted. Account: {account}",
        'logon_success': "An account was successfully logged on. Account: {account}",
        'logon_failure': "An account failed to log on. Account: {account}. Reason: {reason}",
        'explicit_logon': "A logon was attempted using explicit credentials. Account: {account}",
        'credential_read': "An attempt was made to access an account's credentials. Account: {account}",
        'special_privileges': "Special privileges assigned to new logon for {account}",
        'service_install': "A service was installed in the system. Service Name: {service}",
        'service_start': "The {service} service entered the running state",
        'service_stop': "The {service} service entered the stopped state",
        'multiple_failures': "Multiple failed logon attempts detected for account: {account}",
        'account_lockout': "Account {account} has been locked out",
        'account_unlock': "Account {account} was unlocked",
        'password_reset': "An attempt was made to reset an account's password. Account: {account}",
        'logoff': "An account was logged off. Account: {account}"
    }
    
    base_message = templates.get(event_type, "Unknown event occurred")
    
    # Add context-specific information
    if 'logon_failure' in event_type:
        reasons = ["Invalid username or password", "Account expired", "Account disabled", "Time restriction violation"]
        base_message = base_message.format(account=account['name'], reason=random.choice(reasons))
    elif 'service' in event_type:
        service_name = sequence_gen.get_service_name(device, event_type == 'service_install')
        base_message = base_message.format(service=service_name)
    else:
        base_message = base_message.format(account=account['name'])
    
    # Add anomaly indicators if applicable
    if anomalous:
        suspicious_additions = [
            " [Unusual time of day]",
            " [Unusual source location]",
            " [Multiple rapid attempts]",
            " [Privilege escalation detected]"
        ]
        base_message += random.choice(suspicious_additions)
    
    return base_message

def generate_realistic_time(log_date, is_anomalous=False):
    """
    Generate a realistic timestamp based on the base date and anomaly status.
    Anomalous events are more likely to occur during off-hours.
    """
    # Define time patterns
    working_hours = {
        'start': 8,  # 8 AM
        'end': 17,   # 5 PM
        'lunch_start': 12,  # 12 PM
        'lunch_end': 13     # 1 PM
    }
    
    # Get hour and minute
    hour = log_date.hour
    minute = log_date.minute
    
    if is_anomalous:
        # Anomalous events are more likely during off-hours
        if random.random() < 0.7:  # 70% chance of off-hours
            # Off-hours: 6 PM - 7 AM
            hour = random.randint(18, 23) if random.random() < 0.5 else random.randint(0, 7)
        else:
            # During working hours but at unusual times
            hour = random.randint(working_hours['start'], working_hours['end'])
            if working_hours['lunch_start'] <= hour <= working_hours['lunch_end']:
                hour = random.choice([working_hours['lunch_start'] - 1, working_hours['lunch_end'] + 1])
    else:
        # Normal events follow working hours pattern
        if random.random() < 0.9:  # 90% chance during working hours
            hour = random.randint(working_hours['start'], working_hours['end'])
            # Avoid lunch hour for normal events
            if working_hours['lunch_start'] <= hour <= working_hours['lunch_end']:
                hour = random.choice([working_hours['lunch_start'] - 1, working_hours['lunch_end'] + 1])
        else:
            # Some normal events can occur during off-hours
            hour = random.randint(18, 23) if random.random() < 0.5 else random.randint(0, 7)
    
    # Generate realistic minute
    minute = random.randint(0, 59)
    
    # Create new datetime with generated hour and minute
    new_time = log_date.replace(hour=hour, minute=minute)
    
    # Ensure the time is within the valid range
    if new_time < log_date:
        new_time = log_date
    
    return new_time

def generate_log_entry(event_type, account, device, session_id, log_date, sequence_gen, anomalous=False):
    """Generate a complete log entry"""
    event_id = sequence_gen.generate_event_id(event_type)
    message = generate_realistic_message(event_type, event_id, account, device, session_id, log_date, sequence_gen, anomalous)
    
    # Generate realistic timestamp
    generated_time = generate_realistic_time(log_date, anomalous)
    
    # Base severity mapping with reduced failure rates
    base_severity_mapping = {
        'logon_attempt': {'level': 4, 'event_type': 'SuccessAudit', 'status': 'Information'},
        'logon_success': {'level': 4, 'event_type': 'SuccessAudit', 'status': 'Information'},
        'logon_failure': {'level': 3, 'event_type': 'FailureAudit', 'status': 'Moderate'},
        'explicit_logon': {'level': 3, 'event_type': 'Warning', 'status': 'Moderate'},
        'credential_read': {'level': 1, 'event_type': 'Error', 'status': 'Critical'},
        'special_privileges': {'level': 3, 'event_type': 'Warning', 'status': 'Moderate'},
        'service_install': {'level': 2, 'event_type': 'Error', 'status': 'High'},
        'service_start': {'level': 4, 'event_type': 'SuccessAudit', 'status': 'Information'},
        'service_stop': {'level': 4, 'event_type': 'SuccessAudit', 'status': 'Information'},
        'multiple_failures': {'level': 2, 'event_type': 'FailureAudit', 'status': 'High'},
        'account_lockout': {'level': 3, 'event_type': 'Warning', 'status': 'Moderate'},
        'account_unlock': {'level': 4, 'event_type': 'SuccessAudit', 'status': 'Information'},
        'password_reset': {'level': 3, 'event_type': 'SuccessAudit', 'status': 'Moderate'},
        'logoff': {'level': 4, 'event_type': 'SuccessAudit', 'status': 'Information'}
    }
    
    # Get base severity info
    severity_info = base_severity_mapping.get(event_type, {'level': 4, 'event_type': 'SuccessAudit', 'status': 'Information'})
    
    # Apply probability adjustments to create normal distribution
    # Only elevate severity for a small percentage of events
    if severity_info['level'] == 1:  # For critical events
        if random.random() > 0.05:  # 95% chance to downgrade to level 2
            severity_info = {
                'level': 2,
                'event_type': 'Error',
                'status': 'High'
            }
    elif severity_info['level'] == 2:  # For high events
        if random.random() > 0.15:  # 85% chance to downgrade to level 3
            severity_info = {
                'level': 3,
                'event_type': 'Warning',
                'status': 'Moderate'
            }
    elif severity_info['level'] == 3:  # For moderate events
        if random.random() > 0.3:  # 70% chance to downgrade to level 4
            severity_info = {
                'level': 4,
                'event_type': 'SuccessAudit',
                'status': 'Information'
            }
    
    # Generate IP based on severity and anomaly status
    source_ip = get_ip_for_event(severity_info['level'], anomalous)
    
    # Determine if we should include a technique
    technique = None
    if severity_info['level'] <= 2:  # Critical or High severity
        # Define technique probabilities
        technique_weights = {
            'T1110.001': 0.40,  # Brute Force: Password Guessing (40%)
            'T1098': 0.30,      # Account Manipulation (30%)
            'T1218': 0.30       # Signed Binary Proxy Execution (30%)
        }
        
        # Map event types to techniques
        event_technique_mapping = {
            'logon_failure': 'T1110.001',
            'multiple_failures': 'T1110.001',
            'credential_read': 'T1098',
            'special_privileges': 'T1098',
            'service_install': 'T1218',
            'service_start': 'T1218'
        }
        
        # If the event type has a specific technique, use it
        if event_type in event_technique_mapping:
            technique = event_technique_mapping[event_type]
        else:
            # Otherwise, randomly select a technique based on weights
            technique = random.choices(
                list(technique_weights.keys()),
                weights=list(technique_weights.values())
            )[0]
    
    # Generate realistic OS information
    os_versions = {
        "LAPTOP-45TZ9WK": "Kali Linux 2024.1",
        "Wazuh": "Ubuntu Server 22.04 LTS",
        "WORKSTATION-B7Q4PL": "Windows 10 Enterprise 21H2"
    }
    
    # Generate the log entry
    log_entry = {
        "TimeGenerated": generated_time.strftime('%Y-%m-%d %H:%M:%S +0300'),
        "TimeWritten": generated_time.strftime('%Y-%m-%d %H:%M:%S +0300'),
        "EventID": event_id,
        "Level": severity_info['level'],
        "EventType": severity_info['event_type'],
        "Technique": technique,
        "ComputerName": device,
        "Message": message,
        "AccountName": account['name'],
        "AccountSID": account['sid'],
        "SessionID": session_id,
        "SourceIP": source_ip,
        "LogonType": 3 if 'explicit' in event_type else 2,
        "Status": severity_info['status'],
        "OperatingSystem": os_versions.get(device, "Windows 10 Pro"),
        "IsAnomaly": 1 if anomalous else 0
    }
    
    return log_entry

def calculate_daily_log_count(total_logs, start_date, end_date):
    """Calculate the number of logs to generate per day with random variation"""
    days = (end_date - start_date).days + 1
    
    # Base number of logs per day
    base_logs_per_day = 100000
    
    # Generate daily counts with random variation of ±15,000
    daily_counts = []
    for _ in range(days):
        # Generate random variation between -15,000 and +15,000
        variation = random.randint(-15000, 15000)
        # Calculate daily count ensuring it's not negative
        daily_count = max(base_logs_per_day + variation, 1000)  # Ensure at least 1000 logs per day
        daily_counts.append(daily_count)
    
    return daily_counts

def generate_balanced_dates(start_date, end_date, num_events):
    """Generate balanced dates across the date range"""
    # Calculate logs per day
    daily_counts = calculate_daily_log_count(num_events, start_date, end_date)
    
    # Generate dates
    dates = []
    current_date = start_date
    
    for count in daily_counts:
        # Generate timestamps for this day
        for _ in range(count):
            # Generate random time during the day
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            # Create datetime with random time
            event_time = current_date.replace(
                hour=hour,
                minute=minute,
                second=second,
                microsecond=random.randint(0, 999999)
            )
            dates.append(event_time)
        
        # Move to next day
        current_date += timedelta(days=1)
    
    # Shuffle dates to avoid obvious patterns
    random.shuffle(dates)
    return dates

def main():
    parser = argparse.ArgumentParser(description='Generate realistic security logs')
    parser.add_argument('--anomaly-rate', type=float, default=0.05, help='Rate of anomalous events (0-1)')
    parser.add_argument('--lps', type=int, default=100000, help='Logs per second to generate (default: 100000 for security systems)')
    parser.add_argument('--batch-size', type=int, default=50000, help='Number of logs to generate per batch (default: 50000)')
    parser.add_argument('--show-logs', type=int, default=5, help='Number of recent logs to display (default: 5)')
    args = parser.parse_args()
    
    # Initialize MongoDB connection
    try:
        client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)
        client.server_info()
        db = client["log_anomaly"]
        collection = db["logs"]
        print("Successfully connected to MongoDB")
    except Exception as e:
        print("\nError: Could not connect to MongoDB!")
        print("Please make sure MongoDB is installed and running.")
        print("\nTo start MongoDB:")
        print("1. Open a new terminal")
        print("2. Run: mongod")
        print("\nIf MongoDB is not installed:")
        print("1. Download MongoDB from https://www.mongodb.com/try/download/community")
        print("2. Install it following the instructions")
        print("3. Start the MongoDB service")
        print("\nAfter starting MongoDB, run this script again.")
        return
    
    # Initialize the sequence generator
    sequence_gen = LogSequenceGenerator()
    
    # Set date range from March 5th to current date
    start_date = datetime(2025, 3, 5, tzinfo=timezone(timedelta(hours=3)))
    end_date = datetime.now(timezone(timedelta(hours=3)))
    
    # Calculate total number of events (100,000 ±15,000 per day)
    days = (end_date - start_date).days + 1
    daily_counts = calculate_daily_log_count(None, start_date, end_date)
    total_events = sum(daily_counts)
    
    print(f"Starting log generation from {start_date.date()} to {end_date.date()}...")
    print(f"Generating approximately 100,000 logs per day (±15,000 variation)")
    print(f"Total events to generate: {total_events:,.0f}")
    print(f"Using batch size of {args.batch_size} logs")
    print("Press Ctrl+C to stop the script")
    print("\n" * (args.show_logs + 2))
    
    # Pre-generate some common values
    devices_list = list(devices)
    num_devices = len(devices_list)
    
    # Initialize device counters
    device_counts = {device: 0 for device in devices_list}
    total_count = 0
    last_print_time = time.time()
    print_interval = 0.5
    recent_logs = []
    
    try:
        # Generate balanced dates for all events
        event_dates = generate_balanced_dates(start_date, end_date, total_events)
        
        # Process events in batches
        for i in range(0, len(event_dates), args.batch_size):
            current_batch = min(args.batch_size, len(event_dates) - i)
                batch_logs = []
                
                # Generate batch of events
            for j in range(current_batch):
                event_time = event_dates[i + j]
                    
                    # Randomly select a device
                    device = devices_list[random.randint(0, num_devices - 1)]
                    
                    # Determine if this event should be anomalous
                    is_anomalous = random.random() < args.anomaly_rate
                    
                    # Get or create an account for this device
                    account = sequence_gen.get_account_for_device(device, is_anomalous)
                    
                    # Get or generate a session ID
                    session_id = sequence_gen.get_session_id(device, account['name'])
                    
                    # Get the next event type based on the current state
                    event_type = sequence_gen.get_next_event_type(device, account, session_id, is_anomalous)
                    
                    # Generate the log entry
                    log_entry = generate_log_entry(
                        event_type, account, device, session_id,
                        event_time, sequence_gen, is_anomalous
                    )
                    
                    batch_logs.append(log_entry)
                    device_counts[device] += 1
                    total_count += 1
                    
                    # Store recent log for display
                    recent_logs.append({
                        'time': event_time,
                        'device': device,
                        'event': event_type,
                        'account': account['name']
                    })
                    if len(recent_logs) > args.show_logs:
                        recent_logs.pop(0)
                    
                    # Update account state
                    sequence_gen.update_account_state(account, event_type)
                
                # Bulk insert the batch
                if batch_logs:
                    try:
                        collection.insert_many(batch_logs, ordered=False)
                    except Exception as e:
                        print(f"\nError during batch insert: {e}")
                        print("Attempting to reconnect to MongoDB...")
                        try:
                            client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)
                            client.server_info()
                            collection = client["log_anomaly"]["logs"]
                            collection.insert_many(batch_logs, ordered=False)
                        except Exception as e:
                            print(f"Failed to reconnect: {e}")
                            print("Please check your MongoDB connection and restart the script.")
                            return
            
            # Print statistics and recent logs
            current_time_sec = time.time()
            if current_time_sec - last_print_time >= print_interval:
                # Move cursor up to overwrite previous output
                print(f"\033[{args.show_logs + 2}A", end="")
                
                # Print recent logs
                for log in recent_logs:
                    print(f"\033[K{log['time'].strftime('%Y-%m-%d %H:%M:%S')} | {log['device']} | {log['event']} | {log['account']}")
                
                # Print device-specific counts
                stats = " | ".join([f"{device}: {count}" for device, count in device_counts.items()])
                print(f"\033[KTotal: {total_count} | {stats}")
                print("\033[KPress Ctrl+C to stop the script")
                
                last_print_time = current_time_sec
            
            # Minimal sleep to maintain high throughput
            time.sleep(0.001)
            
    except KeyboardInterrupt:
        print("\nStopping log generation...")
        print("\nFinal Statistics:")
        print(f"Total events generated: {total_count}")
        for device, count in device_counts.items():
            print(f"{device}: {count} events")

if __name__ == "__main__":
    main()