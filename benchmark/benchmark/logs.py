# Copyright(C) Facebook, Inc. and its affiliates.
from datetime import datetime
from glob import glob
from multiprocessing import Pool
from os.path import join
from re import findall, search, IGNORECASE
import re
from statistics import mean

from benchmark.utils import Print


class ParseError(Exception):
    pass


class LogParser:
    def __init__(self, clients, primaries, workers, faults=0):
        inputs = [clients, primaries, workers]
        assert all(isinstance(x, list) for x in inputs)
        assert all(isinstance(x, str) for y in inputs for x in y)
        assert all(x for x in inputs)

        self.faults = faults
        if isinstance(faults, int):
            self.committee_size = len(primaries) + int(faults)
            self.workers = len(workers) // len(primaries)
        else:
            self.committee_size = '?'
            self.workers = '?'

        # Parse the clients logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_clients, clients)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse clients\' logs: {e}')
        self.size, self.rate, self.start, misses, self.sent_samples = zip(*results)
        self.misses = sum(misses)

        # Parse the primaries logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_primaries, primaries)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse nodes\' logs: {e}')
        proposals, commits, self.configs, primary_ips = zip(*results)
        self.proposals = self._merge_results([x.items() for x in proposals])
        self.commits = self._merge_results([x.items() for x in commits])

        # Parse the workers logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_workers, workers)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse workers\' logs: {e}')
        sizes, self.received_samples, workers_ips = zip(*results)
        self.sizes = {k: v for x in sizes for k, v in x.items() if k in self.commits}

        # Determine whether the primary and the workers are collocated.
        self.collocate = set(primary_ips) == set(workers_ips)

        # Check whether clients missed their target rate.
        if self.misses != 0:
            Print.warn(f'Clients missed their target rate {self.misses:,} time(s)')

    def _merge_results(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if k not in merged or merged[k] > v:
                    merged[k] = v
        return merged

    # ---------- helpers ----------

    def _safe_search(self, pattern, text, *, ctx=''):
        m = search(pattern, text)
        if not m:
            raise ParseError(f"Missing expected pattern {pattern!r} in {ctx or 'log'}")
        return m

    def _to_posix(self, string):
        """
        Extract and parse an ISO8601 timestamp from a larger string.
        Accepts forms like:
          2025-08-12T06:09:02.802Z
          2025-08-12T06:09:02Z
          2025-08-12T06:09:02.802+00:00
        and ignores any trailing text (e.g. 'INFO benchmark_client').
        """
        iso_pat = re.compile(
            r'(?P<ts>\d{4}-\d{2}-\d{2}T'
            r'\d{2}:\d{2}:\d{2}'
            r'(?:\.\d+)?'
            r'(?:Z|[+-]\d{2}:\d{2}))'
        )
        m = iso_pat.search(string.strip())
        if not m:
            # Retain old behavior as a fallback (handles already-extracted tokens)
            s = string.replace('Z', '+00:00').strip()
            try:
                return datetime.timestamp(datetime.fromisoformat(s))
            except ValueError:
                raise ParseError(f"Unrecognized timestamp format: {string!r}")
        s = m.group('ts').replace('Z', '+00:00')
        try:
            return datetime.timestamp(datetime.fromisoformat(s))
        except ValueError:
            # Rare fallback formats
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
                try:
                    return datetime.timestamp(datetime.strptime(s, fmt))
                except ValueError:
                    continue
            raise ParseError(f"Unrecognized timestamp format: {string!r}")

    def _first_timestamp_in_log(self, log):
        """
        Find the first timestamp in the client log.
        Works with either bracketed '[...]' or plain ISO timestamps at line start.
        """
        # 1) Try bracketed forms like: [2025-08-12T06:09:02.802Z INFO ...]
        m = re.search(r'\[([^\]]+)\]', log)
        if m:
            return self._to_posix(m.group(1))
        # 2) Try ISO at beginning of a line
        m = re.search(
            r'(?m)^(?P<ts>\d{4}-\d{2}-\d{2}T'
            r'\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))',
            log
        )
        if m:
            return self._to_posix(m.group('ts'))
        raise ParseError("No timestamps found in client log")

    # ---------- parsers ----------

    def _parse_clients(self, log):
        if search(r'Error', log) is not None:
            raise ParseError('Client(s) panicked')

        # size
        size_m = (search(r'Transactions\s+size[:=]\s*(\d+)', log, IGNORECASE)
                  or search(r'\btx[_ ]?size[:=]\s*(\d+)', log, IGNORECASE)
                  or search(r'\bsize[:=]\s*(\d+)\b', log, IGNORECASE)
                  or search(r'Client.*size[ =](\d+)', log, IGNORECASE))
        if not size_m:
            preview = '\n'.join(log.splitlines()[:40])
            raise ParseError(f"Could not find 'Transactions size' in client log.\nPreview:\n{preview}")
        size = int(size_m.group(1))

        # rate
        rate_m = (search(r'Transactions\s+rate[:=]\s*(\d+)', log, IGNORECASE)
                  or search(r'\brate[:=]\s*(\d+)\b', log, IGNORECASE)
                  or search(r'Client.*rate[ =](\d+)', log, IGNORECASE))
        if not rate_m:
            preview = '\n'.join(log.splitlines()[:40])
            raise ParseError(f"Could not find 'Transactions rate' in client log.\nPreview:\n{preview}")
        rate = int(rate_m.group(1))

        # start time: prefer lines with 'Start' token, else first timestamp
        start_m = (search(r'\[([^\]]+)\s.*?\bStart\b', log, IGNORECASE)
                   or search(r'\[([^\]]+)\s.*?\bClient start\b', log, IGNORECASE)
                   or search(r'\[([^\]]+)\s.*?\bStarting\b', log, IGNORECASE))
        start = self._to_posix(start_m.group(1)) if start_m else self._first_timestamp_in_log(log)

        misses = len(findall(r'rate too high', log, IGNORECASE))

        # sample tx lines (accept 'sample transaction' or 'sample tx')
        tmp = (findall(r'\[([^\]]+)\s.*? sample (?:transaction|tx)\s+(\d+)', log, IGNORECASE) or
               findall(r'\[([^\]]+)\s.*? sent sample .*? id[:= ](\d+)', log, IGNORECASE))
        samples = {int(s): self._to_posix(t) for t, s in tmp}

        return size, rate, start, misses, samples

    def _parse_primaries(self, log):
        if search(r'(?:panicked|Error)', log) is not None:
            raise ParseError('Primary(s) panicked')

        tmp = findall(r'\[([^\]]+)\s.*? Created B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        proposals = self._merge_results([tmp])

        tmp = findall(r'\[([^\]]+)\s.*? Committed B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        commits = self._merge_results([tmp])

        configs = {
            'header_size': int(self._safe_search(r'Header size .* (\d+)', log, ctx='primary cfg').group(1)),
            'max_header_delay': int(self._safe_search(r'Max header delay .* (\d+)', log, ctx='primary cfg').group(1)),
            'gc_depth': int(self._safe_search(r'Garbage collection depth .* (\d+)', log, ctx='primary cfg').group(1)),
            'sync_retry_delay': int(self._safe_search(r'Sync retry delay .* (\d+)', log, ctx='primary cfg').group(1)),
            'sync_retry_nodes': int(self._safe_search(r'Sync retry nodes .* (\d+)', log, ctx='primary cfg').group(1)),
            'batch_size': int(self._safe_search(r'Batch size .* (\d+)', log, ctx='primary cfg').group(1)),
            'max_batch_delay': int(self._safe_search(r'Max batch delay .* (\d+)', log, ctx='primary cfg').group(1)),
        }

        ip = self._safe_search(r'booted on ((?:\d{1,3}\.){3}\d{1,3})', log, ctx='primary ip').group(1)
        return proposals, commits, configs, ip

    def _parse_workers(self, log):
        if search(r'(?:panic|Error)', log) is not None:
            raise ParseError('Worker(s) panicked')

        tmp = findall(r'Batch ([^ ]+) contains (\d+) B', log)
        sizes = {d: int(s) for d, s in tmp}

        tmp = findall(r'Batch ([^ ]+) contains sample tx (\d+)', log)
        samples = {int(s): d for d, s in tmp}

        ip = self._safe_search(r'booted on ((?:\d{1,3}\.){3}\d{1,3})', log, ctx='worker ip').group(1)
        return sizes, samples, ip

    def _consensus_throughput(self):
        if not self.commits:
            return 0, 0, 0
        start, end = min(self.proposals.values()), max(self.commits.values())
        duration = max(end - start, 1e-9)
        bytes_ = sum(self.sizes.values())
        bps = bytes_ / duration
        tps = bps / max(self.size[0], 1)
        return tps, bps, duration

    def _consensus_latency(self):
        latency = [c - self.proposals[d] for d, c in self.commits.items() if d in self.proposals]
        return mean(latency) if latency else 0

    def _end_to_end_throughput(self):
        if not self.commits:
            return 0, 0, 0
        start, end = min(self.start), max(self.commits.values())
        duration = max(end - start, 1e-9)
        bytes_ = sum(self.sizes.values())
        bps = bytes_ / duration
        tps = bps / max(self.size[0], 1)
        return tps, bps, duration

    def _end_to_end_latency(self):
        latency = []
        for sent, received in zip(self.sent_samples, self.received_samples):
            for tx_id, batch_id in received.items():
                if batch_id in self.commits and tx_id in sent:
                    start = sent[tx_id]
                    end = self.commits[batch_id]
                    latency.append(end - start)
        return mean(latency) if latency else 0

    def result(self):
        header_size = self.configs[0]['header_size']
        max_header_delay = self.configs[0]['max_header_delay']
        gc_depth = self.configs[0]['gc_depth']
        sync_retry_delay = self.configs[0]['sync_retry_delay']
        sync_retry_nodes = self.configs[0]['sync_retry_nodes']
        batch_size = self.configs[0]['batch_size']
        max_batch_delay = self.configs[0]['max_batch_delay']

        consensus_latency = self._consensus_latency() * 1_000
        consensus_tps, consensus_bps, _ = self._consensus_throughput()
        end_to_end_tps, end_to_end_bps, duration = self._end_to_end_throughput()
        end_to_end_latency = self._end_to_end_latency() * 1_000

        return (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            ' + CONFIG:\n'
            f' Faults: {self.faults} node(s)\n'
            f' Committee size: {self.committee_size} node(s)\n'
            f' Worker(s) per node: {self.workers} worker(s)\n'
            f' Collocate primary and workers: {self.collocate}\n'
            f' Input rate: {sum(self.rate):,} tx/s\n'
            f' Transaction size: {self.size[0]:,} B\n'
            f' Execution time: {round(duration):,} s\n'
            '\n'
            f' Header size: {header_size:,} B\n'
            f' Max header delay: {max_header_delay:,} ms\n'
            f' GC depth: {gc_depth:,} round(s)\n'
            f' Sync retry delay: {sync_retry_delay:,} ms\n'
            f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
            f' batch size: {batch_size:,} B\n'
            f' Max batch delay: {max_batch_delay:,} ms\n'
            '\n'
            ' + RESULTS:\n'
            f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
            f' Consensus BPS: {round(consensus_bps):,} B/s\n'
            f' Consensus latency: {round(consensus_latency):,} ms\n'
            '\n'
            f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
            f' End-to-end BPS: {round(end_to_end_bps):,} B/s\n'
            f' End-to-end latency: {round(end_to_end_latency):,} ms\n'
            '-----------------------------------------\n'
        )

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())

    @classmethod
    def process(cls, directory, faults=0):
        assert isinstance(directory, str)

        clients = []
        for filename in sorted(glob(join(directory, 'client-*.log'))):
            with open(filename, 'r') as f:
                clients.append(f.read())
        primaries = []
        for filename in sorted(glob(join(directory, 'primary-*.log'))):
            with open(filename, 'r') as f:
                primaries.append(f.read())
        workers = []
        for filename in sorted(glob(join(directory, 'worker-*.log'))):
            with open(filename, 'r') as f:
                workers.append(f.read())

        return cls(clients, primaries, workers, faults=faults)
