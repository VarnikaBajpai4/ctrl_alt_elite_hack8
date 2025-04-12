# elf_features.py
import lief
import hashlib
import numpy as np
import re
from sklearn.feature_extraction import FeatureHasher

class FeatureType(object):
    name = ''
    dim = 0

    def __repr__(self):
        return '{}({})'.format(self.name, self.dim)

    def raw_features(self, bytez, lief_binary):
        raise NotImplementedError

    def process_raw_features(self, raw_obj):
        raise NotImplementedError

    def feature_vector(self, bytez, lief_binary):
        return self.process_raw_features(self.raw_features(bytez, lief_binary))


class ByteHistogram(FeatureType):
    name = 'histogram'
    dim = 256

    def raw_features(self, bytez, lief_binary):
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return counts.tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        return counts / (counts.sum() + 1e-5)


class ByteEntropyHistogram(FeatureType):
    name = 'byteentropy'
    dim = 256

    def __init__(self, step=1024, window=2048):
        self.step = step
        self.window = window

    def _entropy_bin_counts(self, block):
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2
        Hbin = min(int(H * 2), 15)
        return Hbin, c

    def raw_features(self, bytez, lief_binary):
        output = np.zeros((16, 16), dtype=np.int32)
        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        return counts / (counts.sum() + 1e-5)


class StringExtractor(FeatureType):
    name = 'strings'
    dim = 1 + 1 + 1 + 96 + 1 + 1 + 1

    def __init__(self):
        super(FeatureType, self).__init__()
        self._allstrings = re.compile(b'[\x20-\x7f]{5,}')
        self._paths = re.compile(rb'/[\w\-_/]+')
        self._urls = re.compile(b'https?://', re.IGNORECASE)
        self._ld_so = re.compile(b'ld[-.]linux')
        self._bin_sh = re.compile(b'/bin/sh')

    def raw_features(self, bytez, lief_binary):
        allstrings = self._allstrings.findall(bytez)
        string_lengths = [len(s) for s in allstrings]
        avlength = np.mean(string_lengths) if string_lengths else 0
        printable_hist = np.zeros(96, dtype=np.int32)
        printable = 0
        if allstrings:
            shifted = [b - 32 for b in b''.join(allstrings) if 32 <= b <= 127]
            printable_hist = np.bincount(shifted, minlength=96)
            printable = printable_hist.sum()
            p = printable_hist.astype(np.float32) / printable
            entropy = -np.sum(p[p > 0] * np.log2(p[p > 0]))
        else:
            entropy = 0

        return {
            'numstrings': len(allstrings),
            'avlength': avlength,
            'printabledist': printable_hist.tolist(),
            'printables': printable,
            'entropy': entropy,
            'paths': len(self._paths.findall(bytez)),
            'urls': len(self._urls.findall(bytez)),
            'ld_so': len(self._ld_so.findall(bytez)),
            'bin_sh': len(self._bin_sh.findall(bytez))
        }

    def process_raw_features(self, raw_obj):
        hist_div = float(raw_obj['printables']) if raw_obj['printables'] > 0 else 1.0
        return np.hstack([
            raw_obj['numstrings'], raw_obj['avlength'], raw_obj['printables'],
            np.asarray(raw_obj['printabledist']) / hist_div,
            raw_obj['entropy'], raw_obj['paths'], raw_obj['urls'],
            raw_obj['ld_so'], raw_obj['bin_sh']
        ]).astype(np.float32)

class ELFHeaderInfo(FeatureType):
    name = "elf_header"
    dim = 64

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return {
                "machine": "UNKNOWN",
                "object_type": "UNKNOWN",
                "entrypoint": 0,
                "flags": []
            }
        return {
            "machine": str(lief_binary.header.machine_type),
            "object_type": str(lief_binary.header.file_type),
            "entrypoint": lief_binary.entrypoint,
            "flags": [str(f) for f in lief_binary.header.flags_list]
        }

    def process_raw_features(self, raw_obj):
        return np.hstack([
            raw_obj['entrypoint'],
            FeatureHasher(16, input_type="string").transform([[raw_obj['machine']]]).toarray()[0],
            FeatureHasher(16, input_type="string").transform([[raw_obj['object_type']]]).toarray()[0],
            FeatureHasher(32, input_type="string").transform([raw_obj['flags']]).toarray()[0]
        ]).astype(np.float32)


class ELFGeneralInfo(FeatureType):
    name = "elf_general"
    dim = 6

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return {
                "entry": 0,
                "num_sections": 0,
                "num_segments": 0,
                "machine": "UNKNOWN",
                "has_nx": False,
                "is_pie": False
            }
        return {
            "entry": lief_binary.entrypoint,
            "num_sections": len(lief_binary.sections),
            "num_segments": len(lief_binary.segments),
            "machine": str(lief_binary.header.machine_type),
            "has_nx": lief_binary.has_nx,
            "is_pie": lief_binary.is_pie
        }

    def process_raw_features(self, raw_obj):
        return np.array([
            raw_obj["entry"],
            raw_obj["num_sections"],
            raw_obj["num_segments"],
            hash(raw_obj["machine"]) % 1000,
            int(raw_obj["has_nx"]),
            int(raw_obj["is_pie"])
        ], dtype=np.float32)


class ELFSectionInfo(FeatureType):
    name = "elf_sections"
    dim = 200

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        return [
            {
                "name": s.name,
                "size": s.size,
                "entropy": s.entropy,
                "vsize": s.virtual_address,
                "flags": str(s.flags).split(".")[-1]
            } for s in lief_binary.sections if s.name
        ]

    def process_raw_features(self, raw_obj):
        if not raw_obj:  # Handle empty list case
            return np.zeros(self.dim, dtype=np.float32)
        name_size = [(s['name'], s['size']) for s in raw_obj]
        name_entropy = [(s['name'], s['entropy']) for s in raw_obj]
        name_vsize = [(s['name'], s['vsize']) for s in raw_obj]
        flags = [s['flags'] for s in raw_obj]
        return np.hstack([
            FeatureHasher(50, input_type="pair").transform([name_size]).toarray()[0],
            FeatureHasher(50, input_type="pair").transform([name_entropy]).toarray()[0],
            FeatureHasher(50, input_type="pair").transform([name_vsize]).toarray()[0],
            FeatureHasher(50, input_type="string").transform([flags]).toarray()[0]
        ]).astype(np.float32)


class ELFLibraryInfo(FeatureType):
    name = "elf_libraries"
    dim = 128

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        return lief_binary.libraries

    def process_raw_features(self, raw_obj):
        if not raw_obj:  # Handle empty list case
            return np.zeros(self.dim, dtype=np.float32)
        return FeatureHasher(self.dim, input_type="string").transform([raw_obj]).toarray()[0]

class ELFExportedSymbols(FeatureType):
    name = "elf_exports"
    dim = 64

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        exports = [sym.name for sym in lief_binary.symbols if sym.exported and sym.name]
        return exports

    def process_raw_features(self, raw_obj):
        if not raw_obj:  # Handle empty list case
            return np.zeros(self.dim, dtype=np.float32)
        return FeatureHasher(self.dim, input_type="string").transform([raw_obj]).toarray()[0].astype(np.float32)


class ELFDynamicTags(FeatureType):
    name = "elf_dynamic"
    dim = 64

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        tags = [str(entry.tag) for entry in lief_binary.dynamic_entries]
        return tags

    def process_raw_features(self, raw_obj):
        if not raw_obj:  # Handle empty list case
            return np.zeros(self.dim, dtype=np.float32)
        return FeatureHasher(self.dim, input_type="string").transform([raw_obj]).toarray()[0].astype(np.float32)


class ELFNoteInfo(FeatureType):
    name = "elf_notes"
    dim = 32

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        notes = [n.name for n in lief_binary.notes if n.name]
        return notes

    def process_raw_features(self, raw_obj):
        if not raw_obj:  # Handle empty list case
            return np.zeros(self.dim, dtype=np.float32)
        return FeatureHasher(self.dim, input_type="string").transform([raw_obj]).toarray()[0].astype(np.float32)


class ELFImportedSymbols(FeatureType):
    name = "elf_imports"
    dim = 64

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        return [s.name for s in lief_binary.imported_functions if s.name]

    def process_raw_features(self, raw_obj):
        if not raw_obj:  # Handle empty list case
            return np.zeros(self.dim, dtype=np.float32)
        return FeatureHasher(self.dim, input_type="string").transform([raw_obj]).toarray()[0].astype(np.float32)


class ELFFeatureExtractor:
    def __init__(self):
        self.features = [
            ByteHistogram(),
            ByteEntropyHistogram(),
            StringExtractor(),
            ELFGeneralInfo(),
            ELFHeaderInfo(),
            ELFSectionInfo(),
            ELFLibraryInfo(),
            ELFExportedSymbols(),
            ELFDynamicTags(),
            ELFNoteInfo(),
            ELFImportedSymbols()
        ]
        self.dim = sum(f.dim for f in self.features)

    def raw_features(self, bytez):
        try:
            lief_binary = lief.ELF.parse(list(bytez))
        except Exception as e:
            print(f"Warning: Error parsing ELF file: {str(e)}")
            lief_binary = None

        features = {"sha256": hashlib.sha256(bytez).hexdigest()}
        
        # Extract features that don't depend on lief_binary first
        for f in self.features:
            if f.name in ['histogram', 'byteentropy', 'strings']:
                try:
                    features[f.name] = f.raw_features(bytez, lief_binary)
                except Exception as e:
                    print(f"Warning: Error extracting {f.name} features: {str(e)}")
                    if f.name == 'histogram':
                        features[f.name] = np.zeros(256).tolist()
                    elif f.name == 'byteentropy':
                        features[f.name] = np.zeros(256).tolist()
                    elif f.name == 'strings':
                        features[f.name] = {
                            'numstrings': 0,
                            'avlength': 0,
                            'printabledist': [0] * 96,
                            'printables': 0,
                            'entropy': 0,
                            'paths': 0,
                            'urls': 0,
                            'ld_so': 0,
                            'bin_sh': 0
                        }

        # Then extract features that depend on lief_binary
        for f in self.features:
            if f.name not in ['histogram', 'byteentropy', 'strings']:
                try:
                    features[f.name] = f.raw_features(bytez, lief_binary)
                except Exception as e:
                    print(f"Warning: Error extracting {f.name} features: {str(e)}")
                    if f.name == 'elf_general':
                        features[f.name] = {
                            "entry": 0,
                            "num_sections": 0,
                            "num_segments": 0,
                            "machine": "UNKNOWN",
                            "has_nx": False,
                            "is_pie": False
                        }
                    elif f.name == 'elf_header':
                        features[f.name] = {
                            "machine": "UNKNOWN",
                            "object_type": "UNKNOWN",
                            "entrypoint": 0,
                            "flags": []
                        }
                    else:
                        features[f.name] = []

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

    def feature_vector(self, bytez):
        return self.process_raw_features(self.raw_features(bytez))
