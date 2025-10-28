# Copyright(C) Facebook, Inc. and its affiliates.
from os.path import join

from benchmark.utils import PathMaker


class CommandMaker:

    @staticmethod
    def cleanup():
        return (
            f'rm -r .db-* ; rm .*.json ; mkdir -p {PathMaker.results_path()}'
        )

    @staticmethod
    def clean_logs():
        return f'rm -r {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile():
        # Local compile used during _config(); remote builds are handled in remote._update()
        return 'cargo build --quiet --release --features benchmark'

    @staticmethod
    def generate_key(filename):
        assert isinstance(filename, str)
        # local keygen uses local binary path; remote will upload generated keys
        return f'./node generate_keys --filename {filename}'

    @staticmethod
    def run_primary(keys, committee, store, parameters, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        # Use BIN_PREFIX if provided; defaults to current dir
        return (f'${{BIN_PREFIX:-.}}/node {v} run --keys {keys} '
                f'--committee {committee} --store {store} '
                f'--parameters {parameters} primary')

    @staticmethod
    def run_worker(keys, committee, store, parameters, id, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'${{BIN_PREFIX:-.}}/node {v} run --keys {keys} '
                f'--committee {committee} --store {store} '
                f'--parameters {parameters} worker --id {id}')

    @staticmethod
    def run_client(address, size, rate, nodes):
        assert isinstance(address, str)
        assert isinstance(size, int) and size > 0
        assert isinstance(rate, int) and rate >= 0
        assert isinstance(nodes, list)
        assert all(isinstance(x, str) for x in nodes)
        nodes = f'--nodes {" ".join(nodes)}' if nodes else ''
        return f'${{BIN_PREFIX:-.}}/benchmark_client {address} --size {size} --rate {rate} {nodes}'

    @staticmethod
    def kill():
        return 'tmux kill-server'

    @staticmethod
    def alias_binaries(origin):
        # Keep original local symlink helper (not used remotely)
        assert isinstance(origin, str)
        node, client = join(origin, 'node'), join(origin, 'benchmark_client')
        return f'rm -f node ; rm -f benchmark_client ; ln -s {node} . ; ln -s {client} .'
