import re
import numpy as np
import hashlib
from sklearn.feature_extraction import FeatureHasher

class FeatureType(object):
    name = ''
    dim = 0

    def __repr__(self):
        return '{}({})'.format(self.name, self.dim)

    def raw_features(self, content, parsed_content):
        raise NotImplementedError

    def process_raw_features(self, raw_obj):
        raise NotImplementedError

    def feature_vector(self, content, parsed_content):
        return self.process_raw_features(self.raw_features(content, parsed_content))

class StringFeatures(FeatureType):
    name = 'strings'
    dim = 100

    def raw_features(self, content, parsed_content):
        # Extract various string patterns
        patterns = {
            'cmd_commands': r'\b(cmd|command|start|run|execute)\b',
            'network_commands': r'\b(ping|net|ipconfig|nslookup|tracert)\b',
            'file_operations': r'\b(copy|move|del|delete|ren|rename)\b',
            'system_commands': r'\b(reg|regedit|taskkill|tasklist|shutdown)\b',
            'powershell': r'\b(powershell|ps)\b',
            'obfuscation': r'(\^|%|!|@|#|\$|&|\*|\(|\)|\{|\}|\[|\]|\||\\|/|"|\'|<|>|,|\.|\?|;|:)',
            'urls': r'https?://[^\s<>"]+|www\.[^\s<>"]+',
            'ip_addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'domains': r'\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b',
            'file_paths': r'[A-Za-z]:\\[^<>:"/\\|?*\n]+|\\\\[^<>:"/\\|?*\n]+'
        }
        
        features = {}
        for name, pattern in patterns.items():
            features[name] = len(re.findall(pattern, content, re.IGNORECASE))
        
        return features

    def process_raw_features(self, raw_obj):
        return np.array(list(raw_obj.values()), dtype=np.float32)

class CommandFeatures(FeatureType):
    name = 'commands'
    dim = 50

    def raw_features(self, content, parsed_content):
        # Extract command features
        commands = content.split('\n')
        features = {
            'num_commands': len(commands),
            'avg_command_length': np.mean([len(cmd) for cmd in commands]),
            'max_command_length': max([len(cmd) for cmd in commands]),
            'min_command_length': min([len(cmd) for cmd in commands]),
            'num_comments': len([c for c in commands if c.strip().startswith('REM') or c.strip().startswith('::')]),
            'num_echo': len([c for c in commands if c.strip().startswith('echo')]),
            'num_set': len([c for c in commands if c.strip().startswith('set')]),
            'num_if': len([c for c in commands if c.strip().startswith('if')]),
            'num_for': len([c for c in commands if c.strip().startswith('for')]),
            'num_goto': len([c for c in commands if c.strip().startswith('goto')])
        }
        return features

    def process_raw_features(self, raw_obj):
        return np.array(list(raw_obj.values()), dtype=np.float32)

class BatFeatureExtractor:
    def __init__(self):
        self.features = [
            StringFeatures(),
            CommandFeatures()
        ]
        self.dim = sum(f.dim for f in self.features)

    def raw_features(self, content):
        try:
            # Basic parsing of the batch file
            parsed_content = {
                'lines': content.split('\n'),
                'commands': [line.strip() for line in content.split('\n') if line.strip()]
            }
        except Exception as e:
            print(f"Warning: Error parsing batch file: {str(e)}")
            parsed_content = None

        features = {"sha256": hashlib.sha256(content.encode()).hexdigest()}
        
        for f in self.features:
            try:
                features[f.name] = f.raw_features(content, parsed_content)
            except Exception as e:
                print(f"Warning: Error extracting {f.name} features: {str(e)}")
                features[f.name] = {}

        return features

    def process_raw_features(self, raw_obj):
        feature_vectors = []
        for f in self.features:
            try:
                feature_vectors.append(f.process_raw_features(raw_obj[f.name]))
            except Exception as e:
                print(f"Warning: Error processing {f.name} features: {str(e)}")
                feature_vectors.append(np.zeros(f.dim, dtype=np.float32))
        return np.hstack(feature_vectors).astype(np.float32)

    def feature_vector(self, content):
        return self.process_raw_features(self.raw_features(content))