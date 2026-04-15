"""
Network Scanner - Flask Backend
Supports: active TCP scan + Enterprise Asset Discovery + Shodan/Censys OSINT lookup
"""

import os
import sys

from flask import Flask, request, jsonify, render_template, send_file
from scanner import scan_network, PORT_PRESETS, SERVICES
import threading
import uuid
import requests
import json
from io import BytesIO
from datetime import datetime

# Enterprise discovery modules
try:
    from discovery.orchestrator import run_discovery
    from discovery.ldap_discovery import query_ad
    from reports.excel_report import generate_excel
    from reports.pdf_report import generate_pdf
    ENTERPRISE_AVAILABLE = True
except ImportError as _imp_err:
    ENTERPRISE_AVAILABLE = False
    _enterprise_error = str(_imp_err)

# Support PyInstaller bundle: allow launcher.py to override template/static folders
_template_folder = os.environ.get('FLASK_TEMPLATE_FOLDER', 'templates')
_static_folder   = os.environ.get('FLASK_STATIC_FOLDER',   'static')

app = Flask(__name__, template_folder=_template_folder, static_folder=_static_folder)
app.config['JSON_SORT_KEYS'] = False

# ─── In-memory scan store ─────────────────────────────────────────────────────
scans: dict = {}
asset_scans: dict = {}  # Enterprise asset discovery scans


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── Active Scan ───────────────────────────────────────────────────────────────

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data    = request.get_json(force=True)
    target  = (data.get('target') or '').strip()
    preset  = data.get('preset', 'quick')
    timeout = float(data.get('timeout', 2.0))  # Default: 2 seconds (improved accuracy)
    custom  = data.get('custom_ports', '')

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    # Resolve ports
    if preset == 'custom':
        try:
            ports = list({int(p.strip()) for p in custom.split(',') if p.strip()})
        except ValueError:
            return jsonify({'error': 'Invalid port list'}), 400
    else:
        ports = PORT_PRESETS.get(preset, PORT_PRESETS['quick'])

    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        'id':         scan_id,
        'target':     target,
        'ports':      ports,
        'status':     'running',
        'progress':   0,
        'total':      0,
        'results':    [],
        'start_time': datetime.now().isoformat(),
        'end_time':   None,
        'error':      None,
    }

    def _run():
        try:
            def on_progress(done, total):
                scans[scan_id]['progress'] = done
                scans[scan_id]['total']    = total

            def on_host(host):
                scans[scan_id]['results'].append(host)

            scan_network(target, ports, timeout,
                         progress_cb=on_progress,
                         host_found_cb=on_host)
            scans[scan_id]['status']   = 'complete'
            scans[scan_id]['end_time'] = datetime.now().isoformat()
        except Exception as e:
            scans[scan_id]['status'] = 'error'
            scans[scan_id]['error']  = str(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({'scan_id': scan_id})


@app.route('/api/scan/<scan_id>')
def get_scan(scan_id):
    if scan_id not in scans:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(scans[scan_id])


@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def cancel_scan(scan_id):
    if scan_id in scans:
        scans[scan_id]['status'] = 'cancelled'
    return jsonify({'ok': True})


# ── OSINT Lookup ──────────────────────────────────────────────────────────────

@app.route('/api/osint', methods=['POST'])
def osint_lookup():
    data     = request.get_json(force=True)
    ip       = (data.get('ip') or '').strip()
    provider = data.get('provider', 'shodan')  # 'shodan' | 'censys'
    api_key  = (data.get('api_key') or '').strip()
    api_secret = (data.get('api_secret') or '').strip()

    if not ip:
        return jsonify({'error': 'IP required'}), 400
    if not api_key:
        return jsonify({'error': 'API key required'}), 400

    try:
        if provider == 'shodan':
            result = _shodan_lookup(ip, api_key)
        elif provider == 'censys':
            result = _censys_lookup(ip, api_key, api_secret)
        else:
            return jsonify({'error': 'Unknown provider'}), 400
        return jsonify(result)
    except requests.HTTPError as e:
        code = e.response.status_code if e.response else 0
        msg  = e.response.json().get('error', str(e)) if e.response else str(e)
        return jsonify({'error': f'API error {code}: {msg}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _shodan_lookup(ip: str, api_key: str) -> dict:
    """Query Shodan InternetDB + Host API."""
    # Free InternetDB (no key required, limited data)
    idb = requests.get(f'https://internetdb.shodan.io/{ip}', timeout=10)
    idb.raise_for_status()
    free_data = idb.json()

    result = {
        'provider': 'shodan',
        'ip':       ip,
        'hostnames': free_data.get('hostnames', []),
        'ports':    [{'port': p, 'service': SERVICES.get(p, 'Unknown')}
                     for p in sorted(free_data.get('ports', []))],
        'cpes':     free_data.get('cpes', []),
        'vulns':    free_data.get('vulns', []),
        'tags':     free_data.get('tags', []),
        'source':   'Shodan InternetDB (free)',
    }

    # Try full API if key looks real (not 'free')
    if api_key and api_key.lower() not in ('free', 'none', ''):
        try:
            r = requests.get(
                f'https://api.shodan.io/shodan/host/{ip}',
                params={'key': api_key},
                timeout=15,
            )
            if r.status_code == 200:
                d = r.json()
                result.update({
                    'org':       d.get('org'),
                    'isp':       d.get('isp'),
                    'country':   d.get('country_name'),
                    'city':      d.get('city'),
                    'asn':       d.get('asn'),
                    'os':        d.get('os'),
                    'last_update': d.get('last_update'),
                    'source':    'Shodan Full API',
                    'services':  [
                        {
                            'port':      s.get('port'),
                            'transport': s.get('transport', 'tcp'),
                            'product':   s.get('product', ''),
                            'version':   s.get('version', ''),
                            'banner':    (s.get('data') or '')[:200],
                            'cpe':       s.get('cpe', []),
                        }
                        for s in d.get('data', [])
                    ],
                    'vulns_detail': d.get('vulns', {}),
                })
        except Exception:
            pass  # fall back to InternetDB result

    return result


def _censys_lookup(ip: str, api_id: str, api_secret: str) -> dict:
    """Query Censys v2 API."""
    r = requests.get(
        f'https://search.censys.io/api/v2/hosts/{ip}',
        auth=(api_id, api_secret),
        timeout=15,
    )
    r.raise_for_status()
    d = r.json().get('result', {})

    services = []
    for svc in d.get('services', []):
        services.append({
            'port':      svc.get('port'),
            'transport': svc.get('transport_protocol', 'TCP').lower(),
            'product':   svc.get('software', [{}])[0].get('product', '') if svc.get('software') else '',
            'banner':    (svc.get('banner') or '')[:200],
            'service_name': svc.get('service_name', 'Unknown'),
        })

    loc = d.get('location', {})
    asn = d.get('autonomous_system', {})

    return {
        'provider':  'censys',
        'ip':        ip,
        'hostnames': d.get('dns', {}).get('reverse_dns', {}).get('names', []),
        'ports':     [{'port': s['port'], 'service': s['service_name']} for s in services],
        'services':  services,
        'country':   loc.get('country'),
        'city':      loc.get('city'),
        'org':       asn.get('name'),
        'asn':       f"AS{asn.get('asn', '')}" if asn.get('asn') else None,
        'bgp_prefix': asn.get('bgp_prefix'),
        'last_update': d.get('last_updated_at'),
        'source':    'Censys v2 API',
    }


# ── Enterprise Asset Discovery ────────────────────────────────────────────────

@app.route('/api/asset-scan', methods=['POST'])
def start_asset_scan():
    if not ENTERPRISE_AVAILABLE:
        return jsonify({'error': f'Enterprise modules not loaded: {_enterprise_error}'}), 500

    data = request.get_json(force=True)
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'Target is required'}), 400

    preset  = data.get('preset', 'common')
    timeout = float(data.get('timeout', 2.0))
    custom  = data.get('custom_ports', '')

    if preset == 'custom':
        try:
            ports = list({int(p.strip()) for p in custom.split(',') if p.strip()})
        except ValueError:
            return jsonify({'error': 'Invalid port list'}), 400
    else:
        ports = PORT_PRESETS.get(preset, PORT_PRESETS['common'])

    scan_id = 'a' + str(uuid.uuid4())[:7]
    now = datetime.now()
    asset_scans[scan_id] = {
        'id':          scan_id,
        'target':      target,
        'status':      'running',
        'phase':       'Starting...',
        'progress':    0,
        'total':       0,
        'assets':      [],
        'stats':       {
            'total_assets': 0,
            'by_type': {},
            'by_os': {},
            'discovery_coverage': {},
        },
        'start_time':  now.isoformat(),
        'end_time':    None,
        'error':       None,
    }

    options = {
        'ports':            ports,
        'timeout':          timeout,
        'snmp_communities': data.get('snmp_communities', ['public', 'private']),
        'enable_netbios':   data.get('enable_netbios', True),
        'enable_snmp':      data.get('enable_snmp', True),
        'enable_docker':    data.get('enable_docker', True),
        'enable_dns_sweep': data.get('enable_dns_sweep', True),
    }

    def _run():
        try:
            def on_progress(done, total, phase=''):
                asset_scans[scan_id]['progress'] = done
                asset_scans[scan_id]['total']    = max(total, done)
                if phase:
                    asset_scans[scan_id]['phase'] = phase

            def on_asset(asset_dict):
                asset_scans[scan_id]['assets'].append(asset_dict)
                # Update stats
                stats = asset_scans[scan_id]['stats']
                stats['total_assets'] = len(asset_scans[scan_id]['assets'])
                t = asset_dict.get('asset_type') or 'Unknown'
                stats['by_type'][t] = stats['by_type'].get(t, 0) + 1
                os_fam = asset_dict.get('os_family') or 'Unknown'
                stats['by_os'][os_fam] = stats['by_os'].get(os_fam, 0) + 1
                for m in (asset_dict.get('discovery_methods') or []):
                    stats['discovery_coverage'][m] = \
                        stats['discovery_coverage'].get(m, 0) + 1

            run_discovery(target, options, scan_id=scan_id,
                          on_progress=on_progress, on_asset=on_asset)

            asset_scans[scan_id]['status']   = 'complete'
            asset_scans[scan_id]['end_time'] = datetime.now().isoformat()
            dur = (datetime.now() - now).seconds
            asset_scans[scan_id]['duration'] = f'{dur // 60}m {dur % 60}s'
        except Exception as e:
            asset_scans[scan_id]['status'] = 'error'
            asset_scans[scan_id]['error']  = str(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({'scan_id': scan_id})


@app.route('/api/asset-scan/<scan_id>')
def get_asset_scan(scan_id):
    if scan_id not in asset_scans:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(asset_scans[scan_id])


@app.route('/api/asset-scan/<scan_id>', methods=['DELETE'])
def cancel_asset_scan(scan_id):
    if scan_id in asset_scans:
        asset_scans[scan_id]['status'] = 'cancelled'
    return jsonify({'ok': True})


@app.route('/api/report/excel', methods=['POST'])
def report_excel():
    if not ENTERPRISE_AVAILABLE:
        return jsonify({'error': 'Enterprise modules not loaded'}), 500

    data    = request.get_json(force=True)
    scan_id = data.get('scan_id', '')

    if scan_id in asset_scans:
        assets = asset_scans[scan_id]['assets']
        meta   = {
            'target':    asset_scans[scan_id].get('target'),
            'scan_date': asset_scans[scan_id].get('start_time', '')[:19],
            'duration':  asset_scans[scan_id].get('duration', ''),
        }
    else:
        assets = data.get('assets', [])
        meta   = {}

    try:
        xlsx_bytes = generate_excel(assets, meta)
        filename = f'assets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        return send_file(
            BytesIO(xlsx_bytes),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/pdf', methods=['POST'])
def report_pdf():
    if not ENTERPRISE_AVAILABLE:
        return jsonify({'error': 'Enterprise modules not loaded'}), 500

    data    = request.get_json(force=True)
    scan_id = data.get('scan_id', '')

    if scan_id in asset_scans:
        assets = asset_scans[scan_id]['assets']
        meta   = {
            'target':    asset_scans[scan_id].get('target'),
            'scan_date': asset_scans[scan_id].get('start_time', '')[:19],
            'duration':  asset_scans[scan_id].get('duration', ''),
        }
    else:
        assets = data.get('assets', [])
        meta   = {}

    try:
        pdf_bytes = generate_pdf(assets, meta)
        filename = f'assets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        return send_file(
            BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ldap-query', methods=['POST'])
def ldap_query():
    if not ENTERPRISE_AVAILABLE:
        return jsonify({'error': 'Enterprise modules not loaded'}), 500

    data     = request.get_json(force=True)
    server   = (data.get('server') or '').strip()
    domain   = (data.get('domain') or '').strip()
    username = (data.get('username') or '').strip()
    password = data.get('password', '')

    if not domain or not username:
        return jsonify({'error': 'Domain and username are required'}), 400

    result = query_ad(server, domain, username, password)
    return jsonify(result)


# ── Utilities ─────────────────────────────────────────────────────────────────

@app.route('/api/presets')
def get_presets():
    return jsonify({
        name: {'count': len(ports), 'ports': ports}
        for name, ports in PORT_PRESETS.items()
    })


if __name__ == '__main__':
    print('\n  Network Scanner running at http://127.0.0.1:5000\n')
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
