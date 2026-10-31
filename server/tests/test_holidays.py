from datetime import datetime

from lintel_server.protocol import Decision, Reason
from test_server import env, resp  # noqa: F401


def test_holiday_closes_business_schedules_but_not_24_7(env):
    store, ctl, client, panel, gid = env
    scheds = {s["name"]: s for s in client.get("/api/schedules").json()}
    assert scheds["24/7"]["observe_holidays"] == 0 and scheds["Business hours"]["observe_holidays"] == 1

    allday = client.post("/api/schedules", json={"name": "Every day", "observe_holidays": True,
                                                 "windows": [{"days": 127, "start_min": 0, "end_min": 1440}]}).json()["id"]
    office = client.post("/api/groups", json={"name": "Office", "schedule_id": allday, "doors": [1]}).json()["id"]
    client.post("/api/cardholders", json={"first_name": "Ana", "pin": "3691", "groups": [office]})
    client.post("/api/cardholders", json={"first_name": "Guard", "pin": "8642", "groups": [gid]})  # 24/7 group
    assert resp(panel.pin("3691"))[1] == Decision.GRANT

    today = datetime.now().strftime("%Y-%m-%d")
    assert client.post("/api/holidays", json={"day": today, "name": "Test Day"}).status_code == 200
    assert client.post("/api/holidays", json={"day": today, "name": "Again"}).status_code == 409
    assert client.post("/api/holidays", json={"day": "2026-02-30", "name": "Nope"}).status_code == 422

    assert resp(panel.pin("3691"))[2] == Reason.OUTSIDE_SCHEDULE
    assert resp(panel.pin("8642"))[1] == Decision.GRANT

    hid = client.get("/api/holidays").json()[0]["id"]
    client.delete(f"/api/holidays/{hid}")
    assert resp(panel.pin("3691"))[1] == Decision.GRANT
