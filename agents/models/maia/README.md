# Maia

Maia chess (CSSLab, github.com/CSSLab/maia-chess, release v1.0), one network
per rating band 1100-1900, converted to ONNX with Leela Chess Zero 0.32.1.
Licensed GPL-3.0. These ONNX files are the source of truth; the API runs the
same weights with numpy, extracted into ../maia-npz by
`python -m agents.maia_net convert` (agents/maia_net.py), and they are left out
of the deployed function. `agents/golden/maia-conformance.json` holds lc0's own
policy for 52 positions, which the encoding matches within 0.06%.
