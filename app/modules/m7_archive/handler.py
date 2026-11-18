from flask import Blueprint, jsonify, render_template
from app.config import TITLE, MODULES, SHORT
from app.errors import DomainError
from app.web import api
from app import store
from app.modules.m7_archive import vault
from app.modules.m7_archive.evidence import verify_pack
from app.modules.m7_archive.export_out import sealed_checksum

bp = Blueprint('m7_archive', __name__)


@bp.get('/m7_archive')
def screen():
    history = store.history()
    run = store.get(history[0]['id']) if history else None
    reg = vault.registry()
    packs = {s['run_id']: s for s in reg['seals']}
    current_pack = vault.load_pack(run['run_id']) if run and run['run_id'] in packs else None
    verify_report = None
    if current_pack is not None:
        ok, findings = verify_pack(current_pack)
        verify_report = {'ok': ok, 'findings': findings,
                         'export_sha256': sealed_checksum(run['run_id']),
                         'raw_purged': packs[run['run_id']].get('raw_purged', False)}
    # 页面材料直接取自封存包；未封存时才回退到运行态预览，并明确标注。
    data = current_pack if current_pack is not None else api(7).get_json()
    return render_template('m7_archive.html', title=TITLE, short=SHORT, modules=MODULES, current=7,
                           data=data, run=run or {}, history=history, registry=reg,
                           pack=current_pack, verify_report=verify_report)


@bp.route('/api/m7_archive', methods=['GET', 'POST'])
def preview():
    return api(7)


@bp.post('/api/archive/<run_id>/seal')
def seal(run_id):
    state = store.get(run_id)
    if not state.get('reconcile', {}).get('balanced'):
        raise DomainError('UNBALANCED', '对账未平，禁止封存')
    from app.modules.m7_archive.service import seal_run
    _, pack = seal_run(state)
    store.save(run_id, state)
    return jsonify({'run_id': run_id, 'pack_hash': pack['pack_hash'], 'created': state['archive']['pack_created']})


@bp.get('/api/archive/<run_id>/pack')
def pack(run_id):
    pack = vault.load_pack(run_id)
    if pack is None:
        raise DomainError('NOT_SEALED', '该批次尚未封存证据', 404)
    return jsonify(pack)


@bp.get('/api/archive/<run_id>/verify')
def verify(run_id):
    return jsonify(vault.verify(run_id))


@bp.get('/api/archive/registry')
def registry_view():
    return jsonify(vault.registry())


@bp.post('/api/archive/<run_id>/purge-raw')
def purge_raw(run_id):
    # 7 天清理：删运行态整表材料 + 证据库登记；证据包本身不动。
    result = store.purge_raw(run_id)
    vault.mark_raw_purged(run_id)
    return jsonify(result)
