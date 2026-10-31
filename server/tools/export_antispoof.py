"""Converts Minivision's Silent-Face anti-spoofing weights (Apache-2.0) to the
ONNX files in server/antispoof/, and proves OpenCV gives the same answers as
PyTorch before writing them.

Needs PyTorch and onnx in a throwaway environment (not the server's):

    python -m venv /tmp/as && /tmp/as/bin/pip install torch onnx onnxscript opencv-python-headless numpy
    /tmp/as/bin/python tools/export_antispoof.py <Silent-Face-Anti-Spoofing checkout> antispoof

Upstream: https://github.com/minivision-ai/Silent-Face-Anti-Spoofing
"""

import hashlib
import sys
from pathlib import Path

import cv2
import numpy as np
import torch

MODELS = {  # upstream weights -> exported name; the name's prefix is the crop scale
    "2.7_80x80_MiniFASNetV2.pth": ("MiniFASNetV2", "antispoof_2.7_80x80_minifasnetv2.onnx"),
    "4_0_0_80x80_MiniFASNetV1SE.pth": ("MiniFASNetV1SE", "antispoof_4.0_80x80_minifasnetv1se.onnx"),
}


def main(repo: Path, out: Path) -> None:
    sys.path.insert(0, str(repo))
    from src.model_lib import MiniFASNet  # upstream model definitions

    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(7)
    probe = rng.integers(0, 256, (4, 3, 80, 80)).astype(np.float32)  # raw BGR 0..255, as upstream feeds it
    for weights, (arch, name) in MODELS.items():
        net = getattr(MiniFASNet, arch)(conv6_kernel=(5, 5))
        state = torch.load(repo / "resources" / "anti_spoof_models" / weights, map_location="cpu", weights_only=True)
        net.load_state_dict({k.removeprefix("module."): v for k, v in state.items()})
        net.eval()
        dst = out / name
        torch.onnx.export(net, torch.zeros(1, 3, 80, 80), str(dst), input_names=["input"], output_names=["logits"],
                          opset_version=13, dynamo=False)
        cv = cv2.dnn.readNetFromONNX(str(dst))
        for x in probe:
            with torch.no_grad():
                want = torch.softmax(net(torch.from_numpy(x[None])), 1).numpy()
            cv.setInput(x[None])
            got = cv.forward()
            got = np.exp(got - got.max()) / np.exp(got - got.max()).sum()
            assert np.allclose(want, got, atol=1e-4), (name, want, got)
        print(f"{name}  sha256={hashlib.sha256(dst.read_bytes()).hexdigest()}  ({dst.stat().st_size} bytes, "
              f"OpenCV matches PyTorch)")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
