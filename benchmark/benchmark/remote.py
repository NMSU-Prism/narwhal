# Copyright(C) Facebook, Inc.
from collections import OrderedDict
from fabric import Connection, ThreadingGroup as Group
from fabric.exceptions import GroupException
from paramiko import RSAKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException
from os.path import basename, splitext
from time import sleep
from math import ceil
from copy import deepcopy
import subprocess

#new added
#import logging
#logging.basicConfig(level=logging.DEBUG)


from benchmark.config import Committee, Key, NodeParameters, BenchParameters, ConfigError
from benchmark.utils import BenchError, Print, PathMaker, progress_bar
from benchmark.commands import CommandMaker
from benchmark.logs import LogParser, ParseError
from benchmark.instance import InstanceManager


class FabricError(Exception):
    def __init__(self, error):
        assert isinstance(error, GroupException)
        message = list(error.result.values())[-1]
        super().__init__(message)


class ExecutionError(Exception):
    pass


class Bench:
    def __init__(self, ctx):
        self.manager = InstanceManager.make()
        self.settings = self.manager.settings
        try:
            ctx.connect_kwargs.pkey = RSAKey.from_private_key_file(self.settings.key_path)
           #new added
            print(f"Key path: {self.settings.key_path}")
           
            self.connect = ctx.connect_kwargs
        except (IOError, PasswordRequiredException, SSHException) as e:
            raise BenchError('Failed to load SSH key', e)

        if hasattr(self.manager, "hosts_with_users"):
            self._ip_user = {h["ip"]: h.get("user") for h in self.manager.hosts_with_users()}
            #new added 
            #print(f"Using SSH user: {user} for IP: {ip}")

        else:
            self._ip_user = {}

    def _host_strings(self, ips):
        out = []
        for ip in ips:
            user = self._ip_user.get(ip) or getattr(self.settings, "ssh_user", "santoshadhikari")
            out.append(f"{user}@{ip}")
        return out

    def _conn_for_ip(self, ip: str) -> Connection:
        user = self._ip_user.get(ip) or getattr(self.settings, "ssh_user", "santoshadhikari")
        return Connection(host=ip, user=user, connect_kwargs=self.connect)

    def _check_stderr(self, output):
        if isinstance(output, dict):
            for x in output.values():
                if x.stderr:
                    raise ExecutionError(x.stderr)
        else:
            if output.stderr:
                raise ExecutionError(output.stderr)

    def install(self):
        Print.info('Installing deps, Rust, and cloning the repo...')
        cmd = [
            # choose package manager
            'PKG="" ; if command -v apt-get >/dev/null 2>&1; then PKG=apt; '
            'elif command -v dnf >/dev/null 2>&1; then PKG=dnf; '
            'elif command -v yum >/dev/null 2>&1; then PKG=yum; '
            'else echo "No supported package manager (apt/dnf/yum) found" >&2; exit 1; fi',

            # update cache
            'if [ "$PKG" = apt ]; then sudo apt-get update; '
            'elif [ "$PKG" = dnf ]; then sudo dnf -y makecache; '
            'else sudo yum -y makecache; fi',

            # base build tools + tmux + extras for common Rust crates
            'if [ "$PKG" = apt ]; then '
              'sudo apt-get -y install build-essential cmake clang git curl tmux pkg-config libssl-dev; '
            'elif [ "$PKG" = dnf ]; then '
              'sudo dnf -y groupinstall "Development Tools" || true; '
              'sudo dnf -y install gcc gcc-c++ make cmake clang git curl tmux pkgconfig openssl-devel; '
            'else '
              'sudo yum -y groupinstall "Development Tools" || true; '
              'sudo yum -y install gcc gcc-c++ make cmake clang git curl tmux pkgconfig openssl-devel; '
            'fi',

            # rustup + PATH
            'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
            'export PATH="$HOME/.cargo/bin:$PATH"',

            # clone if missing, else pull
            f'[ -d {self.settings.repo_name} ] || git clone {self.settings.repo_url} {self.settings.repo_name}',
            f'(cd {self.settings.repo_name} && git pull -f)'
        ]
        ips = self.manager.hosts(flat=True)
        try:
            g = Group(*self._host_strings(ips), connect_kwargs=self.connect)
            g.run(' && '.join(cmd), hide=True)
            Print.heading(f'Initialized testbed of {len(ips)} nodes')
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to install repo on testbed', e)

    def kill(self, hosts=[], delete_logs=False):
        assert isinstance(hosts, list)
        assert isinstance(delete_logs, bool)
        ips = hosts if hosts else self.manager.hosts(flat=True)
        delete_logs_cmd = CommandMaker.clean_logs() if delete_logs else 'true'
        cmd = [delete_logs_cmd, f'({CommandMaker.kill()} || true)']
        try:
            g = Group(*self._host_strings(ips), connect_kwargs=self.connect)
            g.run(' && '.join(cmd), hide=True)
        except GroupException as e:
            raise BenchError('Failed to kill nodes', FabricError(e))

    def _select_hosts(self, bench_parameters):
        if bench_parameters.collocate:
            nodes = max(bench_parameters.nodes)
            hosts = self.manager.hosts()
            if sum(len(x) for x in hosts.values()) < nodes:
                return []
            ordered = zip(*hosts.values())
            ordered = [x for y in ordered for x in y]
            return ordered[:nodes]
        else:
            primaries = max(bench_parameters.nodes)
            hosts = self.manager.hosts()
            if len(hosts.keys()) < primaries:
                return []
            for ips in hosts.values():
                if len(ips) < bench_parameters.workers + 1:
                    return []
            selected = []
            for region in list(hosts.keys())[:primaries]:
                ips = list(hosts[region])[:bench_parameters.workers + 1]
                selected.append(ips)
            return selected

    def _background_run(self, host_ip, command, log_file):
        """Run command in tmux with BIN_PREFIX pointing at release dir."""
        name = splitext(basename(log_file))[0]
        bin_dir = f'$HOME/{self.settings.repo_name}/target/release'

        cmd = (
            f'export BIN_PREFIX="{bin_dir}"; '
            f'mkdir -p $HOME/logs; '
            #f'tmux new -d -s "{name}" "{command} |& tee {log_file} 2>&1"'
            f'tmux new -d -s "{name}" "bash -lc \'{command} > {log_file} 2>&1\'"'

        )
        
        c = self._conn_for_ip(host_ip)
        output = c.run(cmd, hide=True)
        self._check_stderr(output)

    def _update(self, hosts, collocate):
        if collocate:
            ips = list(set(hosts))
        else:
            ips = list(set([x for y in hosts for x in y]))

        Print.info(f'Updating {len(ips)} machines (branch "{self.settings.branch}")...')
        print(f'[ -d {self.settings.repo_name} ] || git clone {self.settings.repo_url} {self.settings.repo_name}')
        cmd = [
                #ensure repo exists
                f'[ -d {self.settings.repo_name} ] || git clone {self.settings.repo_url} {self.settings.repo_name}',
                
                f'(cd {self.settings.repo_name} && git fetch -f)',
                f'(cd {self.settings.repo_name} && git checkout -f {self.settings.branch})',
                f'(cd {self.settings.repo_name} && git pull -f)',
                #cargo on PATH then build all bins with benchmark feature
                'export PATH="$HOME/.cargo/bin:$PATH"',
                f'(cd {self.settings.repo_name} && cargo build --release --features benchmark)',
        ]


        g = Group(*self._host_strings(ips), connect_kwargs=self.connect)

        print(ips)

        # Replace with actual IP and key path
        #conn = Connection(host="10.10.0.30", user="santoshadhikari", connect_kwargs={"key_filename": "/home/santoshadhikari/.ssh/narwhal_rsa"})
        #result = conn.run("whoami && echo ok", hide=True)
        #print(result.stdout)
        
        g.run(' && '.join(cmd), hide=True)

    def _config(self, hosts, node_parameters, bench_parameters):
        Print.info('Generating configuration files...')
        subprocess.run([CommandMaker.cleanup()], shell=True, stderr=subprocess.DEVNULL)

        # Local compile for keygen/tooling
        cmd = CommandMaker.compile().split()
        subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

        subprocess.run([CommandMaker.alias_binaries(PathMaker.binary_path())], shell=True)

        keys = []
        key_files = [PathMaker.key_file(i) for i in range(len(hosts))]
        for filename in key_files:
            cmd = CommandMaker.generate_key(filename).split()
            subprocess.run(cmd, check=True)
            keys += [Key.from_file(filename)]

        names = [x.name for x in keys]

        if bench_parameters.collocate:
            workers = bench_parameters.workers
            addresses = OrderedDict((x, [y] * (workers + 1)) for x, y in zip(names, hosts))
        else:
            addresses = OrderedDict((x, y) for x, y in zip(names, hosts))

        committee = Committee(addresses, self.settings.base_port)
        committee.print(PathMaker.committee_file())
        node_parameters.print(PathMaker.parameters_file())

        names = names[:len(names) - bench_parameters.faults]
        progress = progress_bar(names, prefix='Uploading config files:')
        for i, name in enumerate(progress):
            for ip in committee.ips(name):
                c = self._conn_for_ip(ip)
                c.run(f'{CommandMaker.cleanup()} || true', hide=True)
                c.put(PathMaker.committee_file(), '.')
                c.put(PathMaker.key_file(i), '.')
                c.put(PathMaker.parameters_file(), '.')

        return committee

    def _run_single(self, rate, committee, bench_parameters, debug=False):
        faults = bench_parameters.faults

        hosts = committee.ips()
        self.kill(hosts=hosts, delete_logs=True)

        Print.info('Booting clients...')
        workers_addresses = committee.workers_addresses(faults)
        rate_share = ceil(rate / committee.workers())
        for i, addresses in enumerate(workers_addresses):
            for (id, address) in addresses:
                host = Committee.ip(address)
                cmd = CommandMaker.run_client(
                    address,
                    bench_parameters.tx_size,
                    rate_share,
                    [x for y in workers_addresses for _, x in y]
                )
                log_file = PathMaker.client_log_file(i, id)
                self._background_run(host, cmd, log_file)

        Print.info('Booting primaries...')
        for i, address in enumerate(committee.primary_addresses(faults)):
            host = Committee.ip(address)
            cmd = CommandMaker.run_primary(
                PathMaker.key_file(i),
                PathMaker.committee_file(),
                PathMaker.db_path(i),
                PathMaker.parameters_file(),
                debug=debug
            )
            log_file = PathMaker.primary_log_file(i)
            self._background_run(host, cmd, log_file)

        Print.info('Booting workers...')
        for i, addresses in enumerate(workers_addresses):
            for (id, address) in addresses:
                host = Committee.ip(address)
                cmd = CommandMaker.run_worker(
                    PathMaker.key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.db_path(i, id),
                    PathMaker.parameters_file(),
                    id,
                    debug=debug
                )
                log_file = PathMaker.worker_log_file(i, id)
                self._background_run(host, cmd, log_file)

        duration = bench_parameters.duration
        for _ in progress_bar(range(20), prefix=f'Running benchmark ({duration} sec):'):
            sleep(ceil(duration / 20))
        self.kill(hosts=hosts, delete_logs=False)

    def _logs(self, committee, faults):
        subprocess.run([CommandMaker.clean_logs()], shell=True, stderr=subprocess.DEVNULL)

        workers_addresses = committee.workers_addresses(faults)
        progress = progress_bar(workers_addresses, prefix='Downloading workers logs:')
        for i, addresses in enumerate(progress):
            for id, address in addresses:
                host = Committee.ip(address)
                c = self._conn_for_ip(host)
                c.get(PathMaker.client_log_file(i, id), local=PathMaker.client_log_file(i, id))
                c.get(PathMaker.worker_log_file(i, id), local=PathMaker.worker_log_file(i, id))

        primary_addresses = committee.primary_addresses(faults)
        progress = progress_bar(primary_addresses, prefix='Downloading primaries logs:')
        for i, address in enumerate(progress):
            host = Committee.ip(address)
            c = self._conn_for_ip(host)
            c.get(PathMaker.primary_log_file(i), local=PathMaker.primary_log_file(i))

        Print.info('Parsing logs and computing performance...')
        return LogParser.process(PathMaker.logs_path(), faults=faults)

    def run(self, bench_parameters_dict, node_parameters_dict, debug=False):
        Print.heading('Starting remote benchmark')
        try:
            bench_parameters = BenchParameters(bench_parameters_dict)
            node_parameters = NodeParameters(node_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

        selected_hosts = self._select_hosts(bench_parameters)
        if not selected_hosts:
            Print.warn('There are not enough instances available')
            return

        try:
            self._update(selected_hosts, bench_parameters.collocate)
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to update nodes', e)

        try:
            committee = self._config(selected_hosts, node_parameters, bench_parameters)
        except (subprocess.SubprocessError, GroupException) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to configure nodes', e)

        for n in bench_parameters.nodes:
            committee_copy = deepcopy(committee)
            committee_copy.remove_nodes(committee.size() - n)

            for r in bench_parameters.rate:
                Print.heading(f'\nRunning {n} nodes (input rate: {r:,} tx/s)')
                for i in range(bench_parameters.runs):
                    Print.heading(f'Run {i+1}/{bench_parameters.runs}')
                    try:
                        self._run_single(r, committee_copy, bench_parameters, debug)
                        faults = bench_parameters.faults
                        logger = self._logs(committee_copy, faults)
                        logger.print(PathMaker.result_file(
                            faults,
                            n,
                            bench_parameters.workers,
                            bench_parameters.collocate,
                            r,
                            bench_parameters.tx_size,
                        ))
                    except (subprocess.SubprocessError, GroupException, ParseError) as e:
                        self.kill(hosts=selected_hosts)
                        if isinstance(e, GroupException):
                            e = FabricError(e)
                        Print.error(BenchError('Benchmark failed', e))
                        continue
