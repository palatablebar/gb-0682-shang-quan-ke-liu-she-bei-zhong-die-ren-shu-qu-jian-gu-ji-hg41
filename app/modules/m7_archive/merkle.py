"""域分隔的 SHA-256 Merkle 树。

原始整表在留存期结束后必须删除，因此封存时只把整表的 *根哈希* 与
被采纳观测的 *包含证明* 放进证据包：清理后仍可证明采纳行出自那张表，
而无需保留整表（含未采纳/隔离行的字段值）。
"""
import hashlib

LEAF_PREFIX = b'\x00leaf:'
NODE_PREFIX = b'\x01node:'


def digest(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.hexdigest()


def leaf_hash(payload):
    """原始行叶子：payload 为规范化 JSON 字节。"""
    return digest([LEAF_PREFIX, payload])


def node_hash(left, right):
    # 规范化顺序，保证同层拼接与证明校验一致。
    if left > right:
        left, right = right, left
    return digest([NODE_PREFIX, bytes.fromhex(left), bytes.fromhex(right)])


def build(leaves):
    """leaves: [(line, leaf_hash), ...]，按来源行号排序。

    返回 (root, proof_by_line)。proof 为自叶向根的兄弟节点序列，
    每项 {'sibling': hex, 'position': 'left'|'right'}，
    position 表示当前子树相对兄弟的位置（校验时据此决定拼接顺序）。
    空表根为对空前缀的承诺，而非空串。
    每个节点显式携带其覆盖的叶子行号集合，奇数节点原样提升。
    """
    ordered = sorted(leaves, key=lambda item: item[0])
    if not ordered:
        return digest([LEAF_PREFIX]), {}
    proofs = {line: [] for line, _ in ordered}
    # 节点 = (覆盖行号元组, 哈希)
    level = [((line,), h) for line, h in ordered]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            lines_a, hash_a = level[i]
            if i + 1 == len(level):
                nxt.append(level[i])  # 奇数节点提升，不产生兄弟步骤
                continue
            lines_b, hash_b = level[i + 1]
            parent = node_hash(hash_a, hash_b)
            for line in lines_a:
                proofs[line].append({'sibling': hash_b, 'position': 'left'})
            for line in lines_b:
                proofs[line].append({'sibling': hash_a, 'position': 'right'})
            nxt.append((lines_a + lines_b, parent))
        level = nxt
    return level[0][1], proofs


def verify_inclusion(leaf, proof, root):
    cur = leaf
    for step in proof:
        sibling = step['sibling']
        if step['position'] == 'left':
            cur = node_hash(cur, sibling)
        elif step['position'] == 'right':
            cur = node_hash(sibling, cur)
        else:
            return False
    return cur == root
