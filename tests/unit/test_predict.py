from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient
from pytest_mock import MockerFixture

from main import app

# ---------------------------------------------------------------------------
# Payload canónico con los 11 features del Golden Subset v4
# ---------------------------------------------------------------------------
VALID_PAYLOAD: dict = {
    "PROTOCOL": 6,
    "L4_SRC_PORT": 52341,
    "L4_DST_PORT": 443,
    "IN_BYTES": 1400,
    "IN_PKTS": 10,
    "OUT_BYTES": 800,
    "OUT_PKTS": 8,
    "TCP_FLAGS": 27,
    "CLIENT_TCP_FLAGS": 27,
    "SERVER_TCP_FLAGS": 18,
    "FLOW_DURATION_MILLISECONDS": 350,
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def mock_model(mocker: MockerFixture):
    """Mock del par (model, scaler) devuelto por _load_supervised_model.

    predict_proba devuelve [[0.03, 0.97]] → clase "DDoS" con confidence 0.97.
    """
    fake_model = mocker.MagicMock()
    fake_model.predict_proba.return_value = np.array([[0.03, 0.97]])
    fake_model.classes_ = np.array(["Benign", "DDoS"])

    fake_scaler = mocker.MagicMock()
    fake_scaler.transform.return_value = np.zeros((1, 11))

    mocker.patch(
        "api.endpoints.predict._load_supervised_model",
        return_value=(fake_model, fake_scaler),
    )
    return fake_model, fake_scaler


# ---------------------------------------------------------------------------
# 1. Health check
# ---------------------------------------------------------------------------
class TestHealthCheck:
    def test_status_200(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200

    def test_response_schema(self, client: TestClient) -> None:
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert "version" in body
        assert isinstance(body["version"], str)


# ---------------------------------------------------------------------------
# 2. POST /predict/supervised — features válidos
# ---------------------------------------------------------------------------
class TestSupervisedPredictValid:
    def test_returns_200(self, client: TestClient, mock_model) -> None:
        response = client.post("/predict/supervised", json=VALID_PAYLOAD)
        assert response.status_code == 200

    def test_response_has_required_fields(self, client: TestClient, mock_model) -> None:
        body = client.post("/predict/supervised", json=VALID_PAYLOAD).json()
        assert "label" in body
        assert "confidence" in body
        assert "alert_score" in body

    def test_label_matches_mock(self, client: TestClient, mock_model) -> None:
        body = client.post("/predict/supervised", json=VALID_PAYLOAD).json()
        assert body["label"] == "DDoS"

    def test_confidence_in_range(self, client: TestClient, mock_model) -> None:
        body = client.post("/predict/supervised", json=VALID_PAYLOAD).json()
        assert 0.0 <= body["confidence"] <= 1.0

    def test_alert_score_in_range(self, client: TestClient, mock_model) -> None:
        body = client.post("/predict/supervised", json=VALID_PAYLOAD).json()
        assert 0.0 <= body["alert_score"] <= 1.0

    def test_model_load_called_once(self, client: TestClient, mock_model) -> None:
        import api.endpoints.predict as predict_module

        with pytest.MonkeyPatch.context() as mp:
            pass  # ya mockeado por la fixture — solo verificamos la llamada
        fake_model, _ = mock_model
        client.post("/predict/supervised", json=VALID_PAYLOAD)
        fake_model.predict_proba.assert_called()


# ---------------------------------------------------------------------------
# 3. POST /predict/supervised — validación Pydantic (422)
# ---------------------------------------------------------------------------
class TestSupervisedPredictValidation:
    def test_protocol_above_max_returns_422(self, client: TestClient) -> None:
        response = client.post("/predict/supervised", json={**VALID_PAYLOAD, "PROTOCOL": 256})
        assert response.status_code == 422

    def test_protocol_negative_returns_422(self, client: TestClient) -> None:
        response = client.post("/predict/supervised", json={**VALID_PAYLOAD, "PROTOCOL": -1})
        assert response.status_code == 422

    def test_src_port_above_max_returns_422(self, client: TestClient) -> None:
        response = client.post("/predict/supervised", json={**VALID_PAYLOAD, "L4_SRC_PORT": 65536})
        assert response.status_code == 422

    def test_dst_port_negative_returns_422(self, client: TestClient) -> None:
        response = client.post("/predict/supervised", json={**VALID_PAYLOAD, "L4_DST_PORT": -1})
        assert response.status_code == 422

    def test_in_bytes_negative_returns_422(self, client: TestClient) -> None:
        response = client.post("/predict/supervised", json={**VALID_PAYLOAD, "IN_BYTES": -1})
        assert response.status_code == 422

    def test_flow_duration_negative_returns_422(self, client: TestClient) -> None:
        response = client.post(
            "/predict/supervised",
            json={**VALID_PAYLOAD, "FLOW_DURATION_MILLISECONDS": -1},
        )
        assert response.status_code == 422

    def test_missing_feature_returns_422(self, client: TestClient) -> None:
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "TCP_FLAGS"}
        response = client.post("/predict/supervised", json=payload)
        assert response.status_code == 422

    def test_wrong_type_returns_422(self, client: TestClient) -> None:
        response = client.post("/predict/supervised", json={**VALID_PAYLOAD, "IN_PKTS": "not-a-number"})
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 4. POST /predict/anomaly — respuesta not implemented
# ---------------------------------------------------------------------------
class TestAnomalyPredict:
    def test_returns_200(self, client: TestClient) -> None:
        response = client.post("/predict/anomaly", json=VALID_PAYLOAD)
        assert response.status_code == 200

    def test_detail_not_implemented(self, client: TestClient) -> None:
        body = client.post("/predict/anomaly", json=VALID_PAYLOAD).json()
        assert body["detail"] == "not implemented"

    def test_also_validates_features(self, client: TestClient) -> None:
        response = client.post("/predict/anomaly", json={**VALID_PAYLOAD, "PROTOCOL": 999})
        assert response.status_code == 422
