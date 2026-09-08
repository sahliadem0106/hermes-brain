# Coding Challenge CTF Reference

## Common Problem Categories Encountered

### 1. Set Membership (Granary Seal)
Given N items in each of K categories and M queries with one value per category, count queries where ALL values exist in their respective sets.
- **Solution**: Build hash sets per category, iterate queries with O(1) lookups
- **Input**: Categories first (count + list per category), then queries

### 2. Greedy Matching / Scheduling (Toll Schedule)
Given N arrival times and G clearance times (G >= N), assign each arrival to a clearance at or after its time to minimize sum of (clearance - arrival).
- **Solution**: Sort both ascending, two-pointer: for each clearance assign the next unassigned convoy
- **Guarantee**: A valid assignment always exists

### 3. Subsequence with Gap Constraint (Ash Record)
Given a sequence of P materials and N residue (timestamp, material) pairs with min_gap, find the longest prefix of the sequence that can be matched by a subsequence of residues where consecutive matches have time difference >= min_gap.
- **Solution**: Group residues by material, sort each group by timestamp. For each sequence step, binary search for earliest residue >= last_time + min_gap

### 4. Minimum Vertex Cut (Rumour Spine)
Given a directed graph, find minimum nodes (excluding source and target) to remove to disconnect source from target.
- **Solution**: Vertex splitting (v_in → v_out with capacity 1, or INF for S/T) + Dinic max flow
- Node v becomes v_in = v, v_out = v + N. Edge u→v becomes u_out → v_in with INF capacity

### 5. XOR Path Existence (Vow Engine)
Given an undirected graph with edge weights and Q queries (u, v, T), check if a path exists between u and v where XOR of edge weights = T.
- **Solution**: Spanning tree (DFS) → compute XOR distances from root → collect cycle XORs from non-tree edges → insert into XOR linear basis → for each query check if T ^ dist[u] ^ dist[v] is representable by the basis
- **XOR Basis**: Array of 60 ints (bits 59..0). Insert: reduce x by highest set bit, if basis empty at that bit, store it. Can: attempt to reduce x to 0

## Submit Pattern
```python
import json, urllib.request
code = open('solve.py').read()
data = json.dumps({'language': 'python', 'code': code}).encode()
req = urllib.request.Request(f'http://<target>:<port>/run', data=data,
    headers={'Content-Type': 'application/json'})
resp = urllib.request.urlopen(req, timeout=15)
result = json.loads(resp.read())
if result.get('challengeCompleted'):
    print('FLAG:', result['flag'])
```
