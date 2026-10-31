# Face anti-spoofing models

ONNX conversions of the two models from Minivision's
[Silent-Face-Anti-Spoofing](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
(Apache-2.0, see [LICENSE-Silent-Face-Anti-Spoofing.txt](LICENSE-Silent-Face-Anti-Spoofing.txt)),
used by `lintel_server/liveness.py` during guided face enrolment.

| File | Upstream weights | Crop scale | SHA-256 |
|---|---|---|---|
| `antispoof_2.7_80x80_minifasnetv2.onnx` | `2.7_80x80_MiniFASNetV2.pth` | 2.7 | `1cb86b65b7e204950a10a868049e1012c0892f6f908dc93587f29cf3b3794419` |
| `antispoof_4.0_80x80_minifasnetv1se.onnx` | `4_0_0_80x80_MiniFASNetV1SE.pth` | 4.0 | `0a4539e34fd8428967614df33657edbc8ffc0404049104a22dc7eb1589f378a9` |

Reproduce with `server/tools/export_antispoof.py`, which loads the upstream
weights, exports them, and checks that OpenCV's output matches PyTorch's
before writing. The Docker build checks these hashes.
