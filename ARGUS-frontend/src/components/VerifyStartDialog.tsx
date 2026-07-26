import { VerifyOptionsPanel } from "./VerifyOptionsPanel";
import { DEFAULT_VERIFY_OPTIONS, type VerifyOptions } from "../lib/verifyOptions";
import { StartOptionsDialog } from "./StartOptionsDialog";

export function VerifyStartDialog({
  open,
  initialOptions,
  onClose,
  onStart,
}: {
  open: boolean;
  initialOptions: VerifyOptions;
  onClose: () => void;
  onStart: (options: VerifyOptions) => void;
}) {
  return (
    <StartOptionsDialog
      open={open}
      titleId="verify-start-title"
      title="Verify options"
      description="Ready > Verified — 실행 전에 방법을 선택하세요."
      initialOptions={initialOptions}
      defaultOptions={DEFAULT_VERIFY_OPTIONS}
      onClose={onClose}
      onStart={onStart}
      startLabel="Start Verify"
      isStartDisabled={(opts) => !opts.useHttpx && !opts.useSpider && !opts.useAjaxSpider}
    >
      {(options, setOptions) => (
        <VerifyOptionsPanel
          options={options}
          onChange={setOptions}
        />
      )}
    </StartOptionsDialog>
  );
}
