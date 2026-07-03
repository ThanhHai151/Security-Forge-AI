import { useCallback, useRef } from "react";

const DOUBLE_CLICK_DELAY_MS = 250;

// A real double-click fires the browser's native click twice *and then* dblclick — so wiring
// onSingle to onClick directly would run it twice on every double-click. This holds a single
// click for DOUBLE_CLICK_DELAY_MS; if a second click lands in that window it's cancelled and
// onDouble runs instead, otherwise onSingle fires alone.
export function useSingleOrDoubleClick(onSingle, onDouble) {
  const timerRef = useRef(null);

  const onClick = useCallback(
    (...args) => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
        return;
      }
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        onSingle(...args);
      }, DOUBLE_CLICK_DELAY_MS);
    },
    [onSingle]
  );

  const onDoubleClick = useCallback(
    (...args) => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      onDouble(...args);
    },
    [onDouble]
  );

  return { onClick, onDoubleClick };
}
