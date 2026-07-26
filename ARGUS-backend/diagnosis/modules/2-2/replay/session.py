"""2-2 replay session — UI flows + screenshot capture policy."""

from __future__ import annotations

from diagnosis.replay.recorder import ReplayRecorder, ReplaySession


def _ui_flows():
    from diagnosis.g22_replay import load

    return load("ui_flows")


class G22ReplayRecorder(ReplayRecorder):
    """Replay recorder with 2-2 UI flows and dedicated screenshot module capture."""

    def _capture_modes(self, *modes: str) -> list[str]:
        return [mode for mode in modes if mode != "evidence_screenshot"]

    def prepend_ui_flow(self, *, method: str, path: str) -> bool:
        ui_flows = _ui_flows()
        flow = ui_flows.match_ui_flow(method=method, path=path)
        if not flow:
            return False
        ui_steps = ui_flows.ui_flow_to_replay_steps(flow, public_base_url=self.public_base)
        self.steps = ui_steps + self.steps
        return True

    def append_ui_flow(self, *, method: str, path: str) -> bool:
        ui_flows = _ui_flows()
        flow = ui_flows.match_ui_flow(method=method, path=path)
        if not flow:
            return False
        ui_steps = ui_flows.ui_flow_to_replay_steps(
            flow,
            public_base_url=self.public_base,
            step_offset=len(self.steps),
        )
        self.steps.extend(ui_steps)
        return True


class G22ReplaySession(ReplaySession):
    """Per-scan 2-2 replay session."""

    def recorder(
        self,
        *,
        rule_id: str,
        path: str = "",
        trigger: str = "",
    ) -> G22ReplayRecorder:
        return G22ReplayRecorder(
            section_id=self.section_id,
            rule_id=rule_id,
            artifacts_root=self.artifacts_root,
            raw_config=self.raw_config,
            account_auth=self.account_auth,
            trigger=trigger,
            path=path,
        )
