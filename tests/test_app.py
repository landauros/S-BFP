from __future__ import annotations

import base64
import io
import os
import tempfile
import unittest
from pathlib import Path

from PIL import Image


_TEST_DATA = tempfile.TemporaryDirectory(prefix="s_bfp_tests_")
os.environ["S_BFP_DATA_DIR"] = _TEST_DATA.name
os.environ["S_BFP_OPEN_BROWSER"] = "0"
os.environ["S_BFP_SERVER_SECRET"] = "artifact-test-server-secret"
os.environ["S_BFP_SESSION_SECRET"] = "artifact-test-session-secret"

import app as app_module  # noqa: E402


def png_data_url(width: int, height: int) -> str:
    image = Image.new("RGBA", (width, height), (255, 255, 255, 255))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


class ArtifactApplicationTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()
        with app_module._session_lock:
            app_module._clear_session_locked()
        for path in (Path(_TEST_DATA.name) / "users").glob("*.json"):
            path.unlink()

    def register(self, username="artifact_user"):
        response = self.client.post(
            "/register",
            json={"username": username, "consent": True},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "ok")
        return payload

    def acquire(self, username="artifact_user"):
        response = self.client.post("/session/acquire", json={"username": username})
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def test_pages_and_static_assets(self):
        for route in (
            "/",
            "/webgl/",
            "/webgl/utils/initShader.js",
            "/webgl/utils/mat4.js",
            "/webgl/preliminary_fingerprint.js",
            "/audio/",
            "/canvas/",
        ):
            with self.subTest(route=route):
                response = self.client.get(route)
                try:
                    self.assertEqual(response.status_code, 200)
                finally:
                    response.close()

    def test_registration_requires_consent(self):
        response = self.client.post("/register", json={"username": "no_consent"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "error")

    def test_session_requires_authentication(self):
        response = self.client.post("/session/acquire", json={"username": "unknown"})
        self.assertEqual(response.status_code, 401)

    def test_register_login_and_session_lifecycle(self):
        registration = self.register()
        password = registration["password"]
        acquired = self.acquire()
        token = acquired["token"]

        heartbeat = self.client.post(
            "/session/heartbeat",
            json={"username": "artifact_user", "token": token},
        )
        self.assertEqual(heartbeat.status_code, 200)

        released = self.client.post(
            "/session/release",
            json={"username": "artifact_user", "token": token},
        )
        self.assertEqual(released.status_code, 200)

        second_client = app_module.app.test_client()
        login = second_client.post(
            "/login",
            json={"username": "artifact_user", "password": password},
        )
        self.assertEqual(login.status_code, 200)

    def test_rendering_configuration_and_upload_routes(self):
        webgl = self.client.get("/webgl/get_triangles/5/test-seed/1200/900")
        self.assertEqual(webgl.status_code, 200)
        self.assertEqual(len(webgl.get_json()["triangle"]), 5)

        webgl_upload = self.client.post(
            "/webgl/upload_img/test-seed",
            data=png_data_url(1200, 900).encode("ascii"),
        )
        self.assertEqual(webgl_upload.status_code, 200)
        self.assertIn("hash", webgl_upload.get_json())

        audio = self.client.get(
            "/audio/get_snippets_config/test-seed/100/44100/9/20/80/200/2000"
        )
        self.assertEqual(audio.status_code, 200)
        self.assertEqual(len(audio.get_json()["frequencies"]), 9)

        canvas = self.client.get("/canvas/get_string_config/test-seed/5/1200/900")
        self.assertEqual(canvas.status_code, 200)
        self.assertEqual(len(canvas.get_json()["strings"]), 5)

        canvas_upload = self.client.post(
            "/canvas/upload_img/test-seed",
            json={"data": png_data_url(1200, 900)},
        )
        self.assertEqual(canvas_upload.status_code, 200)
        self.assertIn("hash", canvas_upload.get_json())

    def test_authenticated_results_are_persisted_without_direct_identifiers(self):
        self.register()
        self.acquire()

        fingerprint = self.client.post(
            "/user/fingerprint",
            json={
                "username": "artifact_user",
                "fingerprintHash": "fingerprint-hash",
                "fingerprintString": "sensitive-raw-string",
                "fingerprint": {
                    "platform": "test-platform",
                    "userAgent": "sensitive-user-agent",
                    "canvasFingerprint": "data:image/png;base64,sensitive",
                },
            },
        )
        self.assertEqual(fingerprint.status_code, 200)

        endpoints = {
            "/user/triangle_stability": [{"hash": "triangle"}, {"hash": "triangle"}],
            "/user/audio_stability": [
                {"waveformHash": "audio"},
                {"waveformHash": "audio"},
            ],
            "/user/canvas_stability": [{"hash": "canvas"}, {"hash": "canvas"}],
        }
        for endpoint, runs in endpoints.items():
            with self.subTest(endpoint=endpoint):
                response = self.client.post(
                    endpoint,
                    json={"username": "artifact_user", "seed": "seed", "testRuns": runs},
                )
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.get_json()["allStable"])

        record_path = Path(_TEST_DATA.name) / "users" / "artifact_user.json"
        self.assertTrue(record_path.exists())
        record_text = record_path.read_text(encoding="utf-8")
        self.assertNotIn("sensitive-user-agent", record_text)
        self.assertNotIn("data:image", record_text)
        self.assertNotIn("127.0.0.1", record_text)


if __name__ == "__main__":
    unittest.main()
